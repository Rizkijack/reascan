# Windows counterpart of the cloudflared side of docs/vm-setup.md 5.
#
# The adapter task (reascan-adapter.ps1) only binds 127.0.0.1; this runner is
# what makes it reachable from the live Pages deployment. Until the account has
# a domain for a named tunnel, a quick tunnel is used - its URL is random and
# changes on every start, while a Pages secret only takes effect on the next
# deployment. So on every (re)start this script advertises the fresh URL into
# the VM_ADAPTER_URL secret and redeploys, which keeps the live site pointed at
# the tunnel that is actually running. Once a named tunnel exists, the URL is
# fixed and this sync step simply stops finding anything to change.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$here       = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo       = Split-Path -Parent (Split-Path -Parent $here)
$assetsDir  = Join-Path $repo 'frontend'
$project    = 'reascan'
$origin     = 'http://127.0.0.1:8787'
$stateDir   = Join-Path $env:LOCALAPPDATA 'reascan'
$log        = Join-Path $stateDir 'reascan-tunnel.log'

function Write-Log([string]$msg) {
  "{0}  {1}" -f (Get-Date -Format s), $msg | Add-Content -Path $log -Encoding UTF8
}

if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }

# reascan-adapter.ps1 needs the npm prefix for the same reason (resolveSpawn);
# here it is wrangler, which the secret sync and the redeploy both call. The
# boot-triggered task does not inherit an interactive PATH, so the npm prefix is
# prepended explicitly — and the sync block below still falls back to npx when
# `wrangler` itself is not resolvable.
foreach ($candidate in @('C:\Program Files\nodejs\node.exe', "$env:LOCALAPPDATA\Programs\nodejs\node.exe")) {
  if (Test-Path $candidate) { $env:PATH = "$(Split-Path $candidate -Parent);G:\NPMGLOBAL;" + $env:PATH; break }
}
$cloudflared = Get-Command cloudflared -ErrorAction SilentlyContinue
if (-not $cloudflared) {
  foreach ($dir in @('C:\Program Files\cloudflared', 'C:\Program Files (x86)\cloudflared')) {
    $exe = Join-Path $dir 'cloudflared.exe'
    if (Test-Path $exe) { $cloudflared = $exe; break }
  }
} else { $cloudflared = $cloudflared.Source }
if (-not $cloudflared) {
  Write-Log 'cloudflared.exe not found - install it or add it to PATH'
  exit 1
}

Write-Log "reascan-tunnel runner up, bridging $origin into $project"

# The quick-tunnel URL lives as long as the cloudflared process does, so it is
# advertised exactly once per start and re-verified only when that process ends.
$lastAdvertised = $null

while ($true) {
  try {
    if ((Get-Item $log -ErrorAction SilentlyContinue).Length -gt 5MB) {
      Move-Item -Force $log ($log + '.old') -ErrorAction SilentlyContinue
    }
  } catch { }

  $errFile = Join-Path $env:TEMP 'reascan-tunnel-err.txt'
  $outFile = Join-Path $env:TEMP 'reascan-tunnel-out.txt'
  Remove-Item $errFile, $outFile -Force -ErrorAction SilentlyContinue
  $proc = Start-Process -FilePath $cloudflared `
    -ArgumentList @('tunnel', '--no-autoupdate', "--url=$origin") `
    -NoNewWindow -PassThru `
    -RedirectStandardError $errFile -RedirectStandardOutput $outFile

  # cloudflared prints the assigned URL on stderr; give it a minute to connect.
  $url = $null
  for ($i = 0; $i -lt 30 -and $null -eq $url; $i++) {
    Start-Sleep -Seconds 2
    if ($proc.HasExited) { break }
    $text = ''
    foreach ($file in @($errFile, $outFile)) {
      $text += (Get-Content $file -Raw -ErrorAction SilentlyContinue)
    }
    $hit = [regex]::Match($text, 'https://[a-z0-9-]+\.trycloudflare\.com')
    if ($hit.Success) { $url = $hit.Value }
  }

  if (-not $url) {
    Write-Log "cloudflared produced no tunnel URL in 60s (exit $($proc.ExitCode)) - restarting"
    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
    Start-Sleep -Seconds 10
    continue
  }

  if ($url -ne $lastAdvertised) {
    Write-Log "tunnel URL: $url"
    # Resolve wrangler once, with an npx fallback: when this sync failed with
    # "wrangler is not recognized" the live site silently kept the previous
    # (dead) tunnel URL until the next restart. A failed attempt is also
    # retried in place — waiting for "the next tunnel start" can mean hours.
    $wranglerCmd = Get-Command wrangler -ErrorAction SilentlyContinue
    if ($wranglerCmd) {
      $exe = $wranglerCmd.Source
      $prefix = @()
    } else {
      Write-Log 'wrangler not on PATH - falling back to npx --yes wrangler'
      $exe = 'npx'
      $prefix = @('--yes', 'wrangler')
    }

    $attempt = 0
    while ($url -ne $lastAdvertised -and -not $proc.HasExited -and $attempt -lt 6) {
      $attempt++
      try {
        Push-Location $repo
        $url | & $exe @prefix pages secret put VM_ADAPTER_URL --project-name $project 2>&1 |
          Out-File -FilePath $log -Append -Encoding UTF8
        # A native command that exits non-zero does not throw; without these
        # checks the failure was recorded as a successful sync.
        if ($LASTEXITCODE -ne 0) { throw "wrangler secret put exited $LASTEXITCODE" }
        & $exe @prefix pages deploy $assetsDir --project-name $project --branch main --commit-dirty=true 2>&1 |
          Select-Object -Last 3 | Out-File -FilePath $log -Append -Encoding UTF8
        if ($LASTEXITCODE -ne 0) { throw "wrangler deploy exited $LASTEXITCODE" }
        $lastAdvertised = $url
        Write-Log 'VM_ADAPTER_URL refreshed and Pages redeployed'
      } catch {
        Write-Log "secret/redeploy sync failed (attempt $attempt): $($_.Exception.Message)"
        if ($url -ne $lastAdvertised -and -not $proc.HasExited -and $attempt -lt 6) {
          Write-Log 'retrying the sync in 30s - the live site still points at the old tunnel'
          Start-Sleep -Seconds 30
        }
      } finally {
        Pop-Location
      }
    }
    if ($url -ne $lastAdvertised) {
      Write-Log "sync still not applied after $attempt attempt(s) - will retry when the tunnel restarts"
    }
  } else {
    Write-Log "tunnel URL unchanged ($url)"
  }

  # Stay parked on this tunnel for its whole life; a restart gets a new URL and
  # a fresh sync.
  while (-not $proc.HasExited) { Start-Sleep -Seconds 10 }
  Write-Log "cloudflared exited ($($proc.ExitCode)) - restarting with a new URL"
}
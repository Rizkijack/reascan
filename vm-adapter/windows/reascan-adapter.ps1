# Windows counterpart of vm-adapter/systemd/reascan-adapter.service.
#
# Sources .env, launches server.js, and keeps it alive. The scheduled task that
# runs this script is registered by install-reascan-adapter.ps1 and is allowed to
# run for ever, so process restarts are handled by the loop here rather than by
# Task Scheduler's policy — that keeps restart behaviour in one reviewable place
# instead of split between a task XML and shell logic.

Set-StrictMode -Version Latest

$here       = Split-Path -Parent $MyInvocation.MyCommand.Path
$adapterDir = Split-Path -Parent $here
$envFile    = Join-Path $adapterDir '.env'
$server     = Join-Path $adapterDir 'server.js'
$stateDir   = Join-Path $env:LOCALAPPDATA 'reascan'
$log        = Join-Path $stateDir 'reascan-adapter.log'
$port       = 8787

function Write-Log([string]$msg) {
  "{0}  {1}" -f (Get-Date -Format s), $msg | Add-Content -Path $log -Encoding UTF8
}

if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }

# reaCli's resolveSpawn scans PATH for the rea package, so the global npm prefix
# must be reachable from a service context, which inherits a bare PATH.
$node = Get-Command node -ErrorAction SilentlyContinue
foreach ($candidate in @('C:\Program Files\nodejs\node.exe', "$env:LOCALAPPDATA\Programs\nodejs\node.exe")) {
  if (-not $node -and (Test-Path $candidate)) { $node = Get-Item $candidate }
}
if (-not $node) {
  Write-Log 'node.exe not found on PATH or in the usual install locations'
  exit 1
}
$nodeDir = Split-Path $node.Source -Parent
$env:PATH = "$nodeDir;G:\NPMGLOBAL;" + $env:PATH

if (-not (Test-Path $envFile)) {
  Write-Log ".env is missing at $envFile - the adapter has nothing to authenticate with"
  exit 1
}

# EnvironmentFile in the systemd unit; values may contain spaces (paths do).
Get-Content $envFile | ForEach-Object {
  if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
    Set-Item -Path ('env:' + $Matches[1]) -Value $Matches[2].Trim()
  }
}

Write-Log "reascan-adapter runner up, watching 127.0.0.1:$port"

while ($true) {
  # One file, one backup: a host that is up for weeks must not grow an unbounded
  # log. Rotated here rather than inside a shell redirect so the move never
  # races the process that is writing.
  try {
    if ((Get-Item $log -ErrorAction SilentlyContinue).Length -gt 5MB) {
      Move-Item -Force $log ($log + '.old') -ErrorAction SilentlyContinue
    }
  } catch { }

  if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds 15
    continue
  }

    Write-Log 'starting node server.js'
  $up = [System.Diagnostics.Stopwatch]::StartNew()
  # `*>>` writes UTF-16 while Add-Content writes UTF-8, so the log would be two
  # encodings in one file and unreadable with a plain tail. Funnelled through
  # Out-File, server.js writes one encoding for its entire life.
  & ($node.Source) $server 2>&1 | Out-File -FilePath $log -Append -Encoding UTF8
  $up.Stop()
  Write-Log "node exited $($LASTEXITCODE) after $([Math]::Round($up.Elapsed.TotalSeconds,1))s"

  # systemd uses RestartSec=10 unconditionally; a fast exit is usually a config
  # error, and back-to-back relaunches just flood the log with the same reason.
  if ($up.Elapsed.TotalSeconds -lt 5) { Start-Sleep -Seconds 10 }
}
# Registers the "reascan-tunnel" scheduled task: the Windows side of the
# cloudflared bridge described in docs/vm-setup.md 5. Runs at boot and never
# times out, same shape as reascan-adapter, so the tunnel comes back with the
# adapter it forwards to after any reboot or crash.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$runner = Join-Path $here 'reascan-tunnel.ps1'

$who = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error 'run from an elevated PowerShell: this task has to survive a reboot'
  exit 1
}

$settings = New-ScheduledTaskSettingsSet `
  -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -MultipleInstances IgnoreNew `
  -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1)

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runner`""

$task = $null
foreach ($logonType in @('S4U', 'Interactive')) {
  $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType $logonType -RunLevel Limited
  try {
    $task = Register-ScheduledTask -TaskName 'reascan-tunnel' `
      -Description 'cloudflared quick tunnel bridging 127.0.0.1:8787 for the reascan Pages project' `
      -Action $action `
      -Trigger (New-ScheduledTaskTrigger -AtStartup) `
      -Principal $principal `
      -Settings $settings -Force `
      -ErrorAction Stop
    break
  } catch {
    Write-Host "LogonType $logonType rejected: $($_.Exception.Message)"
  }
}
if (-not $task) { Write-Error 'could not register reascan-tunnel'; exit 1 }

Start-ScheduledTask -TaskName 'reascan-tunnel'
"reascan-tunnel registered and started. Runner: $runner"
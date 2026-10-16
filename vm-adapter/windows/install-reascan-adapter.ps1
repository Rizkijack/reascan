# Registers the "reascan-adapter" scheduled task as the Windows side of
# vm-adapter/systemd/reascan-adapter.service: starts at boot, never times out,
# and tolerates a machine that sleeps. The runner (reascan-adapter.ps1) never
# exits, so restart-on-failure here is a second line of defence, not the
# recovery path.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$runner = Join-Path $here 'reascan-adapter.ps1'

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
    $task = Register-ScheduledTask -TaskName 'reascan-adapter' `
      -Description 'reascan adapter - REA analysis engine API on 127.0.0.1:8787' `
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
if (-not $task) { Write-Error 'could not register reascan-adapter'; exit 1 }

Start-ScheduledTask -TaskName 'reascan-adapter'
"reascan-adapter registered and started. Runner: $runner"
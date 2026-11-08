<#
  Intune Win32 app: remove ai-governance hooks for __AGENT__. Runs as SYSTEM.
  Uninstall command:
    %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-AIGovernance.ps1
#>
$ErrorActionPreference = "Continue"
$ProgramFiles64 = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$Python = Get-ChildItem -Path (Join-Path $ProgramFiles64 "Python3*\python.exe") -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
$KiroPolicyPath = "__KIRO_POLICY_WINDOWS__"

if ($Python) {
    $UninstallArgs = @((Join-Path $PSScriptRoot "install_hooks.py"), "--agent", "__AGENT__", "--scope", "managed", "--uninstall")
    if ($KiroPolicyPath) { $UninstallArgs += @("--kiro-policy-path", $KiroPolicyPath) }
    & $Python @UninstallArgs
}
Remove-Item -Recurse -Force -Path (Join-Path $ProgramFiles64 "ai-governance") -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force -Path (Join-Path $env:ProgramData "ai-governance") -ErrorAction SilentlyContinue
exit 0

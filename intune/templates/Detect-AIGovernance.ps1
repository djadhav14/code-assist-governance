<#
  Intune Win32 app custom detection script for __AGENT__, version __VERSION__.
  Intune treats the app as installed only when this exits 0 AND writes to STDOUT.
  Upload with "Run script as 32-bit process on 64-bit clients" = No.

  For Kiro it also checks that every user profile still has the global hook file,
  so a deleted hook makes detection fail and Intune reinstalls the app.
#>
$Agent = "__AGENT__"
$ProgramFiles64 = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$GovDir = Join-Path $ProgramFiles64 "ai-governance"
$VersionFile = Join-Path $GovDir "VERSION"

if (-not (Test-Path $VersionFile)) { exit 0 }
if ((Get-Content $VersionFile -Raw).Trim() -ne "__VERSION__") { exit 0 }
if (-not (Test-Path (Join-Path $GovDir "governance_hook.py"))) { exit 0 }

if ($Agent -ne "kiro") {
    $Claude = Join-Path $ProgramFiles64 "ClaudeCode\managed-settings.json"
    if (-not (Test-Path $Claude)) { exit 0 }
    if (-not (Select-String -Path $Claude -SimpleMatch "governance_hook.py" -Quiet)) { exit 0 }
}

if ($Agent -ne "claude") {
    $KiroPolicy = "__KIRO_POLICY_WINDOWS__"
    if (-not $KiroPolicy) { $KiroPolicy = Join-Path $ProgramFiles64 "Kiro\managed-settings.json" }
    if (-not (Test-Path $KiroPolicy)) { exit 0 }
    if (-not (Select-String -Path $KiroPolicy -SimpleMatch "customer-data" -Quiet)) { exit 0 }
    if (-not (Test-Path (Join-Path $env:ProgramData "ai-governance\kiro-hook.cmd"))) { exit 0 }
    $skip = @("public", "all users", "default user", "defaultapppool")
    $profiles = Get-ChildItem -Path (Join-Path $env:SystemDrive "Users") -Directory -ErrorAction SilentlyContinue |
        Where-Object { $skip -notcontains $_.Name.ToLower() }
    foreach ($p in $profiles) {
        $hookFile = Join-Path $p.FullName ".kiro\hooks\ai-governance.json"
        if (-not (Test-Path $hookFile)) { exit 0 }
        # A hook switched off in Kiro's Agent Hooks panel is written back as "enabled": false.
        if (Select-String -Path $hookFile -Pattern '"enabled"\s*:\s*false' -Quiet) { exit 0 }
    }
}

Write-Output "ai-governance __VERSION__ detected for $Agent"
exit 0

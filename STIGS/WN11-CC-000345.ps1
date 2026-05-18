<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000345
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000345/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000345.ps1 

# ==============================
# REMEDIATION
# ==============================

# Create registry path if it does not exist
New-Item `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
    -Force


# Configure STIG-compliant setting
# Value 2 = Force Deny
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
    -Name "LetAppsActivateWithVoiceAboveLock" `
    -Type DWord `
    -Value 2


# Apply policy refresh
gpupdate /force


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING STIG CONFIGURATION ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
    -Name "LetAppsActivateWithVoiceAboveLock"


Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

LetAppsActivateWithVoiceAboveLock : 2

and

LetAppsActivateWithVoiceAboveLock    REG_DWORD    0x2

0x2 = Force Deny (STIG Compliant)

#>

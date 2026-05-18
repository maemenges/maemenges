<#
.SYNOPSIS
    This script prevents users from accessing the device camera while the system is locked.

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000005
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000005/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-00-000210

    # ==============================
# REMEDIATION
# ==============================

Write-Host ""
Write-Host "Applying STIG remediation..." -ForegroundColor Cyan

# Create registry path if it does not exist
New-Item `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
    -Force

# Disable camera on lock screen
# 0 = Disabled
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
    -Name "NoLockScreenCamera" `
    -Type DWord `
    -Value 1

# Apply Group Policy
gpupdate /force


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING LOCK SCREEN CAMERA POLICY ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
    -Name "NoLockScreenCamera"

Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

NoLockScreenCamera : 1

and

NoLockScreenCamera    REG_DWORD    0x1

1 = Camera disabled on lock screen
= STIG Compliant
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$value = (Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
    -Name "NoLockScreenCamera").NoLockScreenCamera

if ($value -eq 1)
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000005 COMPLIANT: Camera access from the lock screen is disabled." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000005 NOT COMPLIANT: Camera access from the lock screen is enabled." -ForegroundColor Red
}

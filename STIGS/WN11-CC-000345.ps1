<#
.SYNOPSIS
    This script disables Basic authentication for WinRM by configuring
the registry and WinRM service settings.

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

Write-Host ""
Write-Host "Applying STIG remediation..." -ForegroundColor Cyan


# Create registry path if missing
New-Item `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Force


# Disable Basic Authentication
# 0 = Disabled
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowBasic" `
    -Type DWord `
    -Value 0


# Configure WinRM service directly
winrm set winrm/config/service/auth '@{Basic="false"}'


# Refresh Group Policy
gpupdate /force


# Restart WinRM service
Restart-Service WinRM


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING REGISTRY CONFIGURATION ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowBasic"


Write-Host ""
Write-Host "==== VERIFYING WINRM CONFIGURATION ====" -ForegroundColor Cyan

winrm get winrm/config/service/auth


Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowBasic


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Registry Output:

AllowBasic : 0

and

AllowBasic    REG_DWORD    0x0


Expected WinRM Output:

Basic = false


0 / false = STIG Compliant
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$value = (Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowBasic").AllowBasic

if ($value -eq 0)
{
    Write-Host ""
    Write-Host "STIG COMPLIANT: Basic authentication is disabled." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG NOT COMPLIANT: Basic authentication is enabled." -ForegroundColor Red
}

<#
.SYNOPSIS
    This script sets the RDP encryption level policy to require High encryption for client connections.

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000290
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000290/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000290.ps1
    
# ==============================
# REMEDIATION
# ==============================

New-Item `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Force

# MinEncryptionLevel:
# 1 = Low
# 2 = Client Compatible
# 3 = High
# 4 = FIPS Compliant
#
# STIG compliant required level is High
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MinEncryptionLevel" `
    -Type DWord `
    -Value 3

gpupdate /force


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING RDP ENCRYPTION LEVEL ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MinEncryptionLevel"

Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

MinEncryptionLevel : 3

and

MinEncryptionLevel    REG_DWORD    0x3

3 = High encryption = STIG Compliant
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$value = (Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MinEncryptionLevel").MinEncryptionLevel

if ($value -eq 3)
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000290 COMPLIANT: RDP encryption level is set to High." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000290 NOT COMPLIANT: RDP encryption level is not set to High." -ForegroundColor Red
}

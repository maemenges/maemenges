<#
.SYNOPSIS
    Requires secure RPC communications for Remote Desktop Session Host to comply with STIG WN11-CC-000285.

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000285
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000285/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000285.ps1

    # ==============================
# REMEDIATION
# ==============================

Write-Host ""
Write-Host "Applying STIG remediation..." -ForegroundColor Cyan

New-Item `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Force

# fEncryptRPCTraffic:
# 1 = Enabled / Require secure RPC communications
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fEncryptRPCTraffic" `
    -Type DWord `
    -Value 1

gpupdate /force


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING SECURE RPC COMMUNICATIONS ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fEncryptRPCTraffic"

Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

fEncryptRPCTraffic : 1

and

fEncryptRPCTraffic    REG_DWORD    0x1

1 = Enabled / STIG Compliant
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$value = (Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fEncryptRPCTraffic").fEncryptRPCTraffic

if ($value -eq 1)
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000285 COMPLIANT: Secure RPC communication is required." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000285 NOT COMPLIANT: Secure RPC communication is not required." -ForegroundColor Red
}

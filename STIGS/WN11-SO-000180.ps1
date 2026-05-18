<#
.SYNOPSIS
    Configures the security option: Network security: Allow LocalSystem NULL session fallback

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000180
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-SO-000180/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-SO-000180

# ==============================
# REMEDIATION
# ==============================

Write-Host ""
Write-Host "Applying STIG remediation..." -ForegroundColor Cyan

New-Item `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" `
    -Force

# allownullsessionfallback:
# 0 = Disabled / STIG Compliant
# 1 = Enabled / Not Compliant
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" `
    -Name "allownullsessionfallback" `
    -Type DWord `
    -Value 0

gpupdate /force


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING NULL SESSION FALLBACK POLICY ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" `
    -Name "allownullsessionfallback"

Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

allownullsessionfallback : 0

and

allownullsessionfallback    REG_DWORD    0x0

0 = Disabled
= STIG Compliant
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$value = (Get-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" `
    -Name "allownullsessionfallback").allownullsessionfallback

if ($value -eq 0)
{
    Write-Host ""
    Write-Host "STIG WN11-SO-000180 COMPLIANT: NTLM NULL session fallback is disabled." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG WN11-SO-000180 NOT COMPLIANT: NTLM NULL session fallback is enabled." -ForegroundColor Red
}

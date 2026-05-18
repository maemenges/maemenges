<#
.SYNOPSIS
    This script configures Windows policy to prevent the system from maintaining connections to both domain and non-domain networks at the same time.

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000060
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000060/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000060

# ==============================
# REMEDIATION
# ==============================

New-Item `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
    -Force

# fBlockNonDomain:
# 1 = Enabled / Block non-domain network connections
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
    -Name "fBlockNonDomain" `
    -Type DWord `
    -Value 1

gpupdate /force


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING NON-DOMAIN NETWORK BLOCK POLICY ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
    -Name "fBlockNonDomain"

Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fBlockNonDomain


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

fBlockNonDomain : 1

and

fBlockNonDomain    REG_DWORD    0x1

1 = Enabled / STIG Compliant
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$value = (Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
    -Name "fBlockNonDomain").fBlockNonDomain

if ($value -eq 1)
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000060 COMPLIANT: Non-domain network connections are blocked when connected to a domain-authenticated network." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000060 NOT COMPLIANT: Policy is not enabled." -ForegroundColor Red
}

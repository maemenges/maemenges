<#
.SYNOPSIS
    Enables the policy: Always prompt for password upon connection

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000280
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000285/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000280.ps1


# ==============================
# REMEDIATION
# ==============================

Write-Host ""
Write-Host "Applying STIG remediation..." -ForegroundColor Cyan

New-Item `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Force

# fPromptForPassword:
# 1 = Enabled / Always prompt for password
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fPromptForPassword" `
    -Type DWord `
    -Value 1

gpupdate /force


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING RDP PASSWORD PROMPT POLICY ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fPromptForPassword"

Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

fPromptForPassword : 1

and

fPromptForPassword    REG_DWORD    0x1

1 = Always prompt for password
= STIG Compliant
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$value = (Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fPromptForPassword").fPromptForPassword

if ($value -eq 1)
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000280 COMPLIANT: RDP always prompts for password upon connection." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000280 NOT COMPLIANT: RDP password prompt policy is not enabled." -ForegroundColor Red
}

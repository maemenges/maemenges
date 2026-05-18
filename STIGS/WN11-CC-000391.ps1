<#
.SYNOPSIS
    Configures the policy: Disable Internet Explorer 11 as a standalone browser

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000391
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000391/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000391.ps1


    # ==============================
# REMEDIATION
# ==============================

Write-Host ""
Write-Host "Applying STIG remediation..." -ForegroundColor Cyan

New-Item `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" `
    -Force

# NotifyDisableIEOptions:
# 0 = Never notify
# 1 = Always notify
# 2 = Notify once per user
#
# STIG compliant setting disables IE as standalone browser.
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" `
    -Name "NotifyDisableIEOptions" `
    -Type DWord `
    -Value 1

gpupdate /force


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING INTERNET EXPLORER DISABLE POLICY ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" `
    -Name "NotifyDisableIEOptions"

Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v NotifyDisableIEOptions


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

NotifyDisableIEOptions : 1

and

NotifyDisableIEOptions    REG_DWORD    0x1

1 = Always notify users that IE is disabled
= STIG Compliant
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$value = (Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" `
    -Name "NotifyDisableIEOptions").NotifyDisableIEOptions

if ($value -eq 1)
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000391 COMPLIANT: Internet Explorer is disabled as a standalone browser." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000391 NOT COMPLIANT: Internet Explorer disable policy is not configured correctly." -ForegroundColor Red
}

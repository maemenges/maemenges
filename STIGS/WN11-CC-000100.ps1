<#
.SYNOPSIS
    Disables HTTP print driver package download by configuring the Point and Print policy setting.

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000100
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000100/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000100.ps1

# ==============================
# REMEDIATION
# ==============================

Write-Host ""
Write-Host "Applying STIG remediation..." -ForegroundColor Cyan

New-Item `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
    -Force

# DisableWebPnPDownload:
# 1 = Prevent downloading print driver packages over HTTP
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
    -Name "DisableWebPnPDownload" `
    -Type DWord `
    -Value 1

gpupdate /force


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING PRINT DRIVER HTTP DOWNLOAD POLICY ====" -ForegroundColor Cyan

Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
    -Name "DisableWebPnPDownload"

Write-Host ""
Write-Host "==== REGISTRY QUERY ====" -ForegroundColor Cyan

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

DisableWebPnPDownload : 1

and

DisableWebPnPDownload    REG_DWORD    0x1

1 = HTTP print driver package downloads are prevented
= STIG Compliant
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$value = (Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
    -Name "DisableWebPnPDownload").DisableWebPnPDownload

if ($value -eq 1)
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000100 COMPLIANT: Print driver packages cannot be downloaded over HTTP." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG WN11-CC-000100 NOT COMPLIANT: HTTP print driver package download is not blocked." -ForegroundColor Red
}

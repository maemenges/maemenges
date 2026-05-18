<#
.SYNOPSIS
    This script disables Bluetooth services and Bluetooth network devices unless Bluetooth is approved by the organization.

.NOTES
    Author          : Mae Menges
    LinkedIn        : linkedin.com/in/mae-menges
    GitHub          : github.com/maemenges
    Date Created    : 2026-05-18
    Last Modified   : 2026-05-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000210
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-00-000210/

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

Write-Host "Disabling Bluetooth services..." -ForegroundColor Cyan

# Disable Bluetooth Support Service
Stop-Service -Name "bthserv" -Force -ErrorAction SilentlyContinue
Set-Service -Name "bthserv" -StartupType Disabled

# Disable Bluetooth User Support Service if present
Get-Service -Name "BluetoothUserService*" -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
    Set-Service -Name $_.Name -StartupType Disabled
}

# Disable Bluetooth radio/device adapters if present
Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | ForEach-Object {
    Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
}


# ==============================
# VERIFICATION
# ==============================

Write-Host ""
Write-Host "==== VERIFYING BLUETOOTH SERVICES ====" -ForegroundColor Cyan

Get-Service -Name "bthserv" -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType

Get-Service -Name "BluetoothUserService*" -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType


Write-Host ""
Write-Host "==== VERIFYING BLUETOOTH DEVICES ====" -ForegroundColor Cyan

Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Select-Object FriendlyName, Status, Class


# ==============================
# EXPECTED COMPLIANT RESULT
# ==============================

<#
Expected Output:

bthserv    Stopped    Disabled

Bluetooth devices should show:
Status : Disabled

If Bluetooth is approved by your organization,
document the approval instead of disabling it.
#>


# ==============================
# OPTIONAL COMPLIANCE CHECK
# ==============================

$btService = Get-Service -Name "bthserv" -ErrorAction SilentlyContinue
$btDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue

if (($btService.Status -eq "Stopped") -and ($btService.StartType -eq "Disabled"))
{
    Write-Host ""
    Write-Host "STIG WN11-00-000210 COMPLIANT: Bluetooth service is disabled." -ForegroundColor Green
}
else
{
    Write-Host ""
    Write-Host "STIG WN11-00-000210 NOT COMPLIANT: Bluetooth service is not disabled." -ForegroundColor Red
}

if ($btDevices)
{
    $enabledBtDevices = $btDevices | Where-Object { $_.Status -ne "Disabled" }

    if ($enabledBtDevices)
    {
        Write-Host "Bluetooth devices are still enabled:" -ForegroundColor Yellow
        $enabledBtDevices | Select-Object FriendlyName, Status
    }
    else
    {
        Write-Host "Bluetooth device adapters are disabled." -ForegroundColor Green
    }
}
else
{
    Write-Host "No Bluetooth devices detected." -ForegroundColor Green
}

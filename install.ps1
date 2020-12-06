Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Source folder
$src = Split-Path -Parent $Myinvocation.mycommand.path

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        if (Get-Command 'pwsh.exe' -ErrorAction SilentlyContinue) {
            # PowerShell version above 5.1
            Start-Process -FilePath 'pwsh.exe' -Verb Runas -ArgumentList $CommandLine
        } else {
            Start-Process -FilePath 'powershell.exe' -Verb Runas -ArgumentList $CommandLine
        }
        Exit
    }
}

try {
    Copy-Item "$src\*" -Destination "${Env:Windir}\PolicyDefinitions" -Exclude '.git' -Force -Recurse 
}
catch {
    Write-Warning 'Unable to copy the files'
    Write-Warning "$_.Exception.Message"
    Pause
    exit 0
}
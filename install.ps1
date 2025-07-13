#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop' # Stop on non-terminating errors to ensure they are caught by try/catch

# Script Information
Write-Output "Starting ADMX/ADML installation script..."

# Source folder (where this script is located)
$SourceDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Output "Source directory: $SourceDirectory"

# Destination folder (Central Store for Group Policy definitions)
$DestinationDirectory = Join-Path -Path $Env:Windir -ChildPath "PolicyDefinitions"
Write-Output "Target destination directory: $DestinationDirectory"

try {
    # Check if the destination directory exists, create if not
    if (-not (Test-Path -Path $DestinationDirectory -PathType Container)) {
        Write-Output "Destination directory '$DestinationDirectory' does not exist. Creating it..."
        New-Item -Path $DestinationDirectory -ItemType Directory -Force | Out-Null
        Write-Output "Destination directory created."
    }

    # Files and folders to exclude from the copy operation
    $Exclusions = @(
        '.git', # Git repository folder
        '*.md', # Markdown files
        '*.ps1', # PowerShell script files (including this one)
        '.vscode', # VS Code workspace settings
        '.github', # GitHub workflow files and configuration
        'LICENSE',
        '.pre-commit-config.yaml'
    )

    Write-Output "Copying ADMX and ADML files from '$SourceDirectory' to '$DestinationDirectory'..."
    Write-Output "Excluding: $($Exclusions -join ', ')"

    # Copy all items from source to destination, excluding specified items
    Copy-Item -Path "$SourceDirectory\*" -Destination $DestinationDirectory -Exclude $Exclusions -Force -Recurse

    Write-Output "ADMX/ADML files copied successfully to '$DestinationDirectory'!"
}
catch {
    Write-Error "Failed to copy ADMX/ADML files."
    Write-Error "Error Details: $($_.Exception.Message)"
    Write-Error "Occurred at: Line $($_.InvocationInfo.ScriptLineNumber) in $($_.InvocationInfo.ScriptName)"
    Pause
    exit 1 # Exit with a non-zero code to indicate failure
}

<#
.SYNOPSIS
Removes inactive domain user profiles based on last logon data stored in registry.

.DESCRIPTION
This script retrieves last logon dates from the registry, determines profiles that have been 
inactive for 180+ days, logs how much disk space will be reclaimed before deletion, and 
deletes stale user profiles while cleaning up the registry.

.PARAMETER RegistryPath
The registry path where user logon data is stored.

.PARAMETER LogPath
The directory path where log files will be stored.

.PARAMETER ThresholdDays
The number of days after which a profile is considered inactive.

.EXAMPLE
.\UserLogonRegistryStamp_DELETION.ps1

.NOTES
Author: 8bits1beard
Date: 2025-01-27
Version: v1.0.0
Source: ../PoSh-Best-Practice/

.LINK
../PoSh-Best-Practice/
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RegistryPath = 'HKLM:\SOFTWARE\Walmart Applications\WindowsEngineeringOS\TrackUserLogon',
    
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = "C:\Windows\Logs\WindowsEngineeringOS",
    
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$ThresholdDays = 180
)

# Define script-level variables
$LogFileName = "TrackUserLogon_Deletion.log"
$ThresholdDate = (Get-Date).AddDays(-$ThresholdDays)

# Enhanced logging function with JSON format and log rotation
function Write-LogMessage {
    <#
    .SYNOPSIS
    Logs messages to a specified file with different log levels and rotates the log file if it exceeds a certain size.

    .DESCRIPTION
    This function writes structured log entries to a file in JSON format. It supports log levels such as Verbose, Warning, Error, Information, and Debug.
    If the log file exceeds the specified maximum size, it is archived with a timestamp.

    .PARAMETER LogLevel
    The level of the log message. Valid values: Verbose, Warning, Error, Information, Debug.

    .PARAMETER Message
    The message to be logged.

    .PARAMETER LogPath
    The directory where the log file will be stored. Defaults to C:\Windows\Logs\WindowsEngineeringOS.

    .PARAMETER LogFileName
    The name of the log file. Defaults to Hide_Recommended_Section_From_StartMenu.log.

    .PARAMETER MaxFileSizeMB
    The maximum size of the log file in megabytes before it is rotated. Defaults to 5 MB.

    .EXAMPLE
    Write-LogMessage -LogLevel "Information" -Message "Script started."

    .EXAMPLE
    Write-LogMessage -LogLevel "Error" -Message "Failed to connect to database." -LogPath "C:\Logs" -LogFileName "app.log"

    .NOTES
    Author: Joshua Walderbach
    Created: 2025 APR 01
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet("Verbose", "Warning", "Error", "Information", "Debug")]
        [string]$LogLevel,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPath = "C:\Windows\Logs\WindowsEngineeringOS",

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFileName = "Hide_Recommended_Section_From_StartMenu.log",

        [Parameter(Position = 4)]
        [int]$MaxFileSizeMB = 5
    )

    begin {
        # Combine the log path and log file name to create the full log file path
        $LogFile = Join-Path -Path $LogPath -ChildPath $LogFileName

        # Create the log directory if it doesn't exist
        if (-not (Test-Path -Path $LogPath)) {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        }

        # Check if the log file exists and its size
        if (Test-Path -Path $LogFile) {
            $FileSizeMB = (Get-Item -Path $LogFile).Length / 1MB
            if ($FileSizeMB -ge $MaxFileSizeMB) {
                # Rotate the log file
                $Timestamp = Get-Date -Format "yyyyMMddHHmmss"
                $ArchivedLogFile = "$LogPath\$($LogFileName)_$Timestamp.log"
                Rename-Item -Path $LogFile -NewName $ArchivedLogFile
            }
        }
    }

    process {
        # Create a log entry with the current timestamp, log level, and message
        $LogEntry = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            Level     = $LogLevel
            Message   = $Message
        }
        $LogEntryJSON = $LogEntry | ConvertTo-Json -Depth 2 -Compress

        try {
            # Write the log entry to the log file
            Add-Content -Path $LogFile -Value $LogEntryJSON -ErrorAction Stop
        } catch {
            # Handle any errors that occur during the log writing process
            Write-Warning "Failed to write log entry: $LogEntryJSON. Error: $($_.Exception.Message)"
        }

        # Output the log message based on the specified log level
        switch ($LogLevel) {
            "Verbose"     { if ($VerbosePreference -ne "SilentlyContinue") { Write-Verbose -Message $Message } }
            "Warning"     { Write-Warning -Message $Message }
            "Error"       { Write-Error -Message $Message }
            "Information" { Write-Information -MessageData $LogEntryJSON -InformationAction Continue }
            "Debug"       { if ($DebugPreference -ne "SilentlyContinue") { Write-Debug -Message $Message } }
        }
    }
}

# Initialize log file with script execution details
Write-LogMessage -LogLevel "Information" -Message "-----------------------------------" -LogPath $LogPath -LogFileName $LogFileName
Write-LogMessage -LogLevel "Information" -Message "Script Execution Started: $(Get-Date)" -LogPath $LogPath -LogFileName $LogFileName
Write-LogMessage -LogLevel "Information" -Message "Registry Path: $RegistryPath" -LogPath $LogPath -LogFileName $LogFileName
Write-LogMessage -LogLevel "Information" -Message "Log File: $(Join-Path -Path $LogPath -ChildPath $LogFileName)" -LogPath $LogPath -LogFileName $LogFileName
Write-LogMessage -LogLevel "Information" -Message "Threshold Date (Inactive for $ThresholdDays+ days): $ThresholdDate" -LogPath $LogPath -LogFileName $LogFileName
Write-LogMessage -LogLevel "Information" -Message "-----------------------------------" -LogPath $LogPath -LogFileName $LogFileName

# Ensure the registry key exists
if (!(Test-Path -Path $RegistryPath)) {
    Write-LogMessage -LogLevel "Error" -Message "Registry path '$RegistryPath' does not exist. Exiting..." -LogPath $LogPath -LogFileName $LogFileName
    exit 1
}

# Function to get profile size in GB
function Get-ProfileSizeGB {
    <#
    .SYNOPSIS
    Calculates the total size of a user profile.

    .PARAMETER ProfilePath
    The full path to the user's profile directory.

    .OUTPUTS
    [decimal] - Profile size in GB (rounded to one decimal place)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfilePath
    )
    
    # Check if profile path exists before calculating size
    if (Test-Path $ProfilePath) {
        try {
            # Get all files in the profile directory and calculate total size
            $Size = (Get-ChildItem -Path $ProfilePath -Recurse -ErrorAction SilentlyContinue | 
                Where-Object { -not $_.PSIsContainer -and $null -ne $_.Length } | 
                Measure-Object -Property Length -Sum).Sum
            
            if ($Size) {
                return [math]::Round($Size / 1GB, 1)  # Convert bytes to GB and round
            }
        }
        catch {
            Write-LogMessage -LogLevel "Warning" -Message "Failed to calculate size for profile '$ProfilePath': $_" -LogPath $LogPath -LogFileName $LogFileName
        }
    }
    return 0
}

# Retrieve all user profiles once for efficiency
$AllUserProfiles = Get-CimInstance -ClassName Win32_UserProfile

# Retrieve exclusion list (system profiles and Moonpie)
$ExcludeProfiles = $AllUserProfiles | 
    Where-Object { $_.Special -eq $true -or $_.LocalPath -like '*\Moonpie' } | 
    ForEach-Object { $_.LocalPath -replace '^.*\\', '' }  # Extract username

Write-LogMessage -LogLevel "Information" -Message "Excluded Profiles: $($ExcludeProfiles -join ', ')" -LogPath $LogPath -LogFileName $LogFileName
Write-LogMessage -LogLevel "Information" -Message "-----------------------------------" -LogPath $LogPath -LogFileName $LogFileName

# Get all registry properties (users and last logon times)
$Values = Get-ItemProperty -Path $RegistryPath

# Exclude default properties that are not user names
$DefaultProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
$UserProperties = $Values.PSObject.Properties | Where-Object { $DefaultProps -notcontains $_.Name }

# Loop through each user stored in the registry
foreach ($Value in $UserProperties) {
    $UserName = $Value.Name
    $LastLogonDate = $null

    try {
        # Parse the last logon date from registry value
        $LastLogonDate = [DateTime]::Parse($Value.Value)
    }
    catch {
        Write-LogMessage -LogLevel "Error" -Message "Failed to parse last logon date for '$UserName'. Skipping..." -LogPath $LogPath -LogFileName $LogFileName
        continue
    }

    Write-LogMessage -LogLevel "Information" -Message "Checking user: $UserName (Last Logon: $LastLogonDate)" -LogPath $LogPath -LogFileName $LogFileName

    # Skip excluded profiles
    if ($UserName -in $ExcludeProfiles) {
        Write-LogMessage -LogLevel "Information" -Message "Skipping excluded user '$UserName'." -LogPath $LogPath -LogFileName $LogFileName
        continue
    }

    # Find the actual profile path from cached WMI data
    $UserProfile = $AllUserProfiles | Where-Object { $_.LocalPath -match "\\$UserName$" }
    
    if ($UserProfile) {
        $ProfilePath = $UserProfile.LocalPath
        
        # Get profile size before any action
        $ProfileSizeGB = Get-ProfileSizeGB -ProfilePath $ProfilePath
        Write-LogMessage -LogLevel "Information" -Message "Estimated profile size for '$UserName': $ProfileSizeGB GB" -LogPath $LogPath -LogFileName $LogFileName

        # Check if user is inactive (180+ days)
        if ($LastLogonDate -lt $ThresholdDate) {
            Write-LogMessage -LogLevel "Information" -Message "User '$UserName' has been inactive for $ThresholdDays+ days. Proceeding with deletion." -LogPath $LogPath -LogFileName $LogFileName
            
            # Check if profile is loaded (in use)
            if ($UserProfile.Loaded) {
                Write-LogMessage -LogLevel "Error" -Message "Cannot delete profile '$UserName' because it is currently loaded (in use). Skipping..." -LogPath $LogPath -LogFileName $LogFileName
                continue
            }
            
            # Check for admin privileges
            if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Write-LogMessage -LogLevel "Error" -Message "Script is not running with administrator privileges. Cannot delete profile '$UserName'." -LogPath $LogPath -LogFileName $LogFileName
                continue
            }
            
            try {
                # Remove the user profile
                $UserProfile.Delete()
                
                # Remove the registry entry
                try {
                    Remove-ItemProperty -Path $RegistryPath -Name $UserName -ErrorAction Stop
                    Write-LogMessage -LogLevel "Information" -Message "SUCCESS: User profile '$UserName' deleted (Last Logon: $LastLogonDate, Size: $ProfileSizeGB GB)." -LogPath $LogPath -LogFileName $LogFileName
                }
                catch {
                    Write-LogMessage -LogLevel "Error" -Message "Failed to remove registry entry for '$UserName'. Error: $_" -LogPath $LogPath -LogFileName $LogFileName
                }
            }
            catch {
                Write-LogMessage -LogLevel "Error" -Message "Failed to delete domain user profile '$UserName'. Error: $_" -LogPath $LogPath -LogFileName $LogFileName
            }
        }
        else {
            Write-LogMessage -LogLevel "Information" -Message "User '$UserName' is still active (Last Logon: $LastLogonDate, Size: $ProfileSizeGB GB). Skipping." -LogPath $LogPath -LogFileName $LogFileName
        }
    }
    else {
        Write-LogMessage -LogLevel "Information" -Message "User profile '$UserName' not found on the system. Removing registry entry..." -LogPath $LogPath -LogFileName $LogFileName
        Remove-ItemProperty -Path $RegistryPath -Name $UserName -ErrorAction SilentlyContinue
    }
}

Write-LogMessage -LogLevel "Information" -Message "-----------------------------------" -LogPath $LogPath -LogFileName $LogFileName
Write-LogMessage -LogLevel "Information" -Message "Script Execution Completed: $(Get-Date)" -LogPath $LogPath -LogFileName $LogFileName
Write-LogMessage -LogLevel "Information" -Message "-----------------------------------" -LogPath $LogPath -LogFileName $LogFileName

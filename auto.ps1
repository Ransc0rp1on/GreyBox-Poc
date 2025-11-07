<#
.SYNOPSIS
    Automated SSH package verification script for Nessus vulnerability assessment

.DESCRIPTION
    This script connects to multiple servers via SSH, checks installed package versions,
    and compares them against Nessus recommended versions to identify vulnerable systems.

.PARAMETER IPs
    Comma-separated list of IP addresses or path to a text file containing IPs

.PARAMETER Username
    SSH username for authentication

.PARAMETER Command
    Command to check package version (e.g., "rpm -q cloud-init")

.PARAMETER RecommendedVersion
    The minimum safe version recommended by Nessus

.PARAMETER KeyPath
    Path to SSH private key for key-based authentication (optional)

.PARAMETER PackageName
    Name of the package being checked (for better reporting)

.PARAMETER Timeout
    SSH connection timeout in seconds (default: 15)

.EXAMPLE
    .\GB-Verification.ps1 -IPs "192.168.1.10,192.168.1.11" -Username "vapt-scan-user" -Command "rpm -q cloud-init" -RecommendedVersion "10.1" -PackageName "cloud-init"

.EXAMPLE
    .\GB-Verification.ps1 -IPs "servers.txt" -Username "vapt-scan-user" -Command "dpkg -l | grep cloud-init" -RecommendedVersion "10.1" -PackageName "cloud-init"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$IPs,
    
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$true)]
    [string]$Command,
    
    [Parameter(Mandatory=$true)]
    [string]$RecommendedVersion,
    
    [Parameter(Mandatory=$false)]
    [string]$KeyPath,
    
    [Parameter(Mandatory=$true)]
    [string]$PackageName,
    
    [Parameter(Mandatory=$false)]
    [int]$Timeout = 15
)

# Script metadata and security warning
Write-Host "=== Nessus Package Verification Script ===" -ForegroundColor Cyan
Write-Host "Authorized use only. All activities are monitored and logged." -ForegroundColor Yellow
Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host ""

# Input validation
function Test-VersionFormat {
    param([string]$Version)
    return $Version -match '^[0-9]+(\.[0-9]+)*([a-zA-Z\-_][a-zA-Z0-9\-_]*)?$'
}

if (-not (Test-VersionFormat $RecommendedVersion)) {
    Write-Error "Invalid recommended version format: $RecommendedVersion"
    Write-Host "Version should be in format: major.minor.patch (e.g., 10.1.0)" -ForegroundColor Yellow
    exit 1
}

# Check and install Posh-SSH module if missing
if (-not (Get-Module -ListAvailable Posh-SSH)) {
    Write-Host "Installing Posh-SSH module..." -ForegroundColor Yellow
    try {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module Posh-SSH -Scope CurrentUser -Force -Confirm:$false -ErrorAction Stop
        Write-Host "Posh-SSH module installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Posh-SSH module: $($_.Exception.Message)"
        exit 1
    }
}

Import-Module Posh-SSH -Force

# Parse IP addresses
$targets = @()
if (Test-Path $IPs -PathType Leaf) {
    try {
        $targets = Get-Content $IPs | Where-Object { $_ -and $_.Trim() -match '^(?:\d{1,3}\.){3}\d{1,3}$' }
        Write-Host "Loaded $($targets.Count) IPs from file: $IPs" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to read IP file: $IPs"
        exit 1
    }
}
else {
    $targets = $IPs -split '[, ]+' | Where-Object { $_ -and $_.Trim() -match '^(?:\d{1,3}\.){3}\d{1,3}$' }
    Write-Host "Processing $($targets.Count) IPs from parameter" -ForegroundColor Green
}

if ($targets.Count -eq 0) {
    Write-Error "No valid IP addresses found. Please check your input."
    exit 1
}

# Authentication handling
if ($KeyPath) {
    # Key-based authentication
    if (-not (Test-Path $KeyPath)) {
        Write-Error "SSH key file not found at: $KeyPath"
        exit 1
    }
    $cred = New-Object System.Management.Automation.PSCredential ($Username, (New-Object System.Security.SecureString))
    Write-Host "Using key-based authentication with: $KeyPath" -ForegroundColor Green
}
else {
    # Password-based authentication
    $cred = Get-Credential -UserName $Username -Message "Enter SSH Password for $Username"
    if (-not $cred) {
        Write-Error "No credentials provided"
        exit 1
    }
    Write-Host "Using password-based authentication" -ForegroundColor Green
}

# Version comparison function
function Compare-Version {
    param(
        [string]$InstalledVersion,
        [string]$RecommendedVersion
    )
    
    try {
        # Normalize version strings by removing non-numeric prefixes/suffixes
        $installedClean = $InstalledVersion -replace '^[^0-9]*' -replace '[^0-9\.].*$'
        $recommendedClean = $RecommendedVersion -replace '^[^0-9]*' -replace '[^0-9\.].*$'
        
        # Split version components
        $installedParts = $installedClean.Split('.') | ForEach-Object { [int]$_ }
        $recommendedParts = $recommendedClean.Split('.') | ForEach-Object { [int]$_ }
        
        # Compare each version component
        for ($i = 0; $i -lt [Math]::Max($installedParts.Length, $recommendedParts.Length); $i++) {
            $installedPart = if ($i -lt $installedParts.Length) { $installedParts[$i] } else { 0 }
            $recommendedPart = if ($i -lt $recommendedParts.Length) { $recommendedParts[$i] } else { 0 }
            
            if ($installedPart -lt $recommendedPart) {
                return $false  # Vulnerable
            }
            elseif ($installedPart -gt $recommendedPart) {
                return $true   # Safe
            }
        }
        return $true  # Versions are equal
    }
    catch {
        Write-Warning "Version comparison failed for '$InstalledVersion' vs '$RecommendedVersion': $($_.Exception.Message)"
        return $false  # Treat comparison failures as vulnerable
    }
}

# Extract version from command output
function Get-VersionFromOutput {
    param(
        [string]$Output,
        [string]$CommandType
    )
    
    if ($CommandType -like "*rpm -q*") {
        # RPM format: package-version-release.architecture
        $match = $Output | Select-String '(\d+\.\d+(?:\.\d+)?(?:-\d+)?)'
        if ($match) { return $match.Matches[0].Groups[1].Value }
    }
    elseif ($CommandType -like "*dpkg*") {
        # DPKG format: ii  package  version  architecture  description
        $match = $Output | Select-String '\s(\d+:)?(\d+\.\d+(?:\.\d+)?(?:-\d+)?)'
        if ($match) { return $match.Matches[0].Groups[2].Value }
    }
    
    # Fallback: extract any version-like pattern
    $versionPattern = '\b\d+\.\d+(?:\.\d+)?(?:-\d+)?\b'
    $match = $Output | Select-String $versionPattern
    if ($match) { return $match.Matches[0].Value }
    
    return $null
}

# Initialize results tracking
$results = @()
$successfulConnections = 0
$vulnerableCount = 0

Write-Host "`nStarting verification for package: $PackageName" -ForegroundColor Cyan
Write-Host "Recommended version: $RecommendedVersion" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan

# Process each target
foreach ($ip in $targets) {
    Write-Host "`nConnecting to $ip..." -ForegroundColor White
    Write-Host "Command: $Command" -ForegroundColor Gray
    
    $session = $null
    $result = @{
        IP = $ip
        Status = "Unknown"
        InstalledVersion = "N/A"
        IsVulnerable = $false
        Error = $null
    }
    
    try {
        # Create SSH session parameters
        $sessionParams = @{
            ComputerName    = $ip
            Credential      = $cred
            AcceptKey       = $true
            ErrorAction     = 'Stop'
            ConnectionTimeout = $Timeout
        }
        if ($KeyPath) {
            $sessionParams.KeyFile = $KeyPath
        }

        # Establish SSH connection
        $session = New-SSHSession @sessionParams
        
        if ($session.Connected) {
            $successfulConnections++
            
            # Execute command
            $sshResult = Invoke-SSHCommand -SSHSession $session -Command $Command -ErrorAction Stop
            
            if ($sshResult.ExitStatus -eq 0) {
                $output = $sshResult.Output -join "`n"
                
                if ($output -and $output.Trim() -notmatch "not installed|not found|No packages found") {
                    # Extract version from output
                    $installedVersion = Get-VersionFromOutput -Output $output -CommandType $Command
                    
                    if ($installedVersion) {
                        $result.InstalledVersion = $installedVersion
                        
                        # Compare versions
                        $isSafe = Compare-Version -InstalledVersion $installedVersion -RecommendedVersion $RecommendedVersion
                        $result.IsVulnerable = -not $isSafe
                        $result.Status = if ($isSafe) { "Compliant" } else { "VULNERABLE" }
                        
                        if ($result.IsVulnerable) {
                            $vulnerableCount++
                            Write-Host "  Version: $installedVersion" -ForegroundColor Red -NoNewline
                            Write-Host " - $($result.Status)" -ForegroundColor Red
                            Write-Host "  [!] This server requires immediate attention!" -ForegroundColor Red
                        }
                        else {
                            Write-Host "  Version: $installedVersion" -ForegroundColor Green -NoNewline
                            Write-Host " - $($result.Status)" -ForegroundColor Green
                        }
                    }
                    else {
                        $result.Status = "Version Parse Error"
                        $result.Error = "Could not extract version from output"
                        Write-Host "  Output: $($output.Trim())" -ForegroundColor Yellow
                        Write-Host "  Status: $($result.Status)" -ForegroundColor Yellow
                    }
                }
                else {
                    $result.Status = "Not Installed"
                    Write-Host "  Package is not installed on this system" -ForegroundColor Blue
                }
            }
            else {
                $result.Status = "Command Failed"
                $result.Error = "Exit code: $($sshResult.ExitStatus), Error: $($sshResult.Error)"
                Write-Host "  Command execution failed" -ForegroundColor Red
                Write-Host "  Error: $($sshResult.Error)" -ForegroundColor Red
            }
        }
        else {
            $result.Status = "Connection Failed"
            $result.Error = "SSH session not established"
            Write-Host "  SSH connection failed" -ForegroundColor Red
        }
    }
    catch {
        $result.Status = "Connection Error"
        $result.Error = $_.Exception.Message
        Write-Host "  Connection Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if ($session) { 
            try { $session | Remove-SSHSession | Out-Null } 
            catch { Write-Warning "Failed to clean up SSH session for $ip" }
        }
    }
    
    $results += New-Object PSObject -Property $result
}

# Generate summary report
Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
Write-Host "SCAN SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Package: $PackageName" -ForegroundColor White
Write-Host "Recommended Version: $RecommendedVersion" -ForegroundColor White
Write-Host "Total Targets: $($targets.Count)" -ForegroundColor White
Write-Host "Successful Connections: $successfulConnections" -ForegroundColor Green
Write-Host "Vulnerable Systems: $vulnerableCount" -ForegroundColor $(if ($vulnerableCount -gt 0) { "Red" } else { "Green" })
Write-Host "Scan Duration: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White

# Display detailed results
if ($vulnerableCount -gt 0) {
    Write-Host "`nVULNERABLE SYSTEMS REQUIRING ATTENTION:" -ForegroundColor Red
    $results | Where-Object { $_.IsVulnerable -eq $true } | ForEach-Object {
        Write-Host "  $($_.IP) - Version: $($_.InstalledVersion)" -ForegroundColor Red
    }
}

# Export results to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = "Nessus_Verification_${PackageName}_${timestamp}.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`nDetailed results exported to: $csvPath" -ForegroundColor Green

# Final status
if ($vulnerableCount -gt 0) {
    Write-Host "`n[ACTION REQUIRED] $vulnerableCount systems are vulnerable and need patching!" -ForegroundColor Red -BackgroundColor Black
    exit 1  # Exit with error code to indicate vulnerabilities found
}
else {
    Write-Host "`n[SUCCESS] All systems are compliant with Nessus recommendations!" -ForegroundColor Green
    exit 0
}

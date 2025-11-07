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
    The minimum safe version string (e.g., "cloud-init-23.4-19.el9_5.6.noarch")

.PARAMETER KeyPath
    Path to SSH private key for key-based authentication (optional)

.EXAMPLE
    .\GB-Verification.ps1 -IPs "192.168.1.10,192.168.1.11" -Username "vapt-scan-user" -Command "rpm -q cloud-init" -RecommendedVersion "cloud-init-23.4-19.el9_5.6.noarch"
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
    [string]$KeyPath
)

# Check and install Posh-SSH module if missing
if (-not (Get-Module -ListAvailable Posh-SSH)) {
    Write-Host "Installing Posh-SSH module..." -ForegroundColor Yellow
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    Install-Module Posh-SSH -Scope CurrentUser -Force -Confirm:$false
}

Import-Module Posh-SSH -Force

# Parse IP addresses
$targets = @()
if (Test-Path $IPs -PathType Leaf) {
    $targets = Get-Content $IPs | Where-Object { $_ -and $_.Trim() -match '^(?:\d{1,3}\.){3}\d{1,3}$' }
}
else {
    $targets = $IPs -split '[, ]+' | Where-Object { $_ -and $_.Trim() -match '^(?:\d{1,3}\.){3}\d{1,3}$' }
}

if ($targets.Count -eq 0) {
    Write-Error "No valid IP addresses found. Please check your input."
    exit 1
}

# Authentication handling
if ($KeyPath) {
    # Key-based authentication
    if (-not (Test-Path $KeyPath)) {
        Write-Error "Key file not found at: $KeyPath"
        exit 1
    }
    $cred = New-Object System.Management.Automation.PSCredential ($Username, (New-Object System.Security.SecureString))
} else {
    # Password-based authentication
    $cred = Get-Credential -UserName $Username -Message "Enter SSH Password"
}

# Function to extract numeric version from package string
function Get-NumericVersion {
    param([string]$PackageString)
    
    # Extract version pattern: numbers and dots between hyphens and extensions
    if ($PackageString -match '-\d+(\.\d+)*[^-]*') {
        $versionPart = $Matches[0].Substring(1)  # Remove the leading hyphen
        
        # Further clean up to get just the numeric version
        if ($versionPart -match '^\d+(\.\d+)*') {
            return $Matches[0]
        }
    }
    return $null
}

# Function to compare RPM-style versions
function Compare-RPMVersions {
    param(
        [string]$InstalledVersion,
        [string]$RecommendedVersion
    )
    
    try {
        # Extract numeric versions
        $installedNumeric = Get-NumericVersion -PackageString $InstalledVersion
        $recommendedNumeric = Get-NumericVersion -PackageString $RecommendedVersion
        
        if (-not $installedNumeric -or -not $recommendedNumeric) {
            return $false  # If we can't parse, assume vulnerable
        }
        
        # Split versions into components
        $installedParts = $installedNumeric.Split('.') | ForEach-Object { [int]$_ }
        $recommendedParts = $recommendedNumeric.Split('.') | ForEach-Object { [int]$_ }
        
        # Compare each component
        for ($i = 0; $i -lt [Math]::Max($installedParts.Length, $recommendedParts.Length); $i++) {
            $installedPart = if ($i -lt $installedParts.Length) { $installedParts[$i] } else { 0 }
            $recommendedPart = if ($i -lt $recommendedParts.Length) { $recommendedParts[$i] } else { 0 }
            
            if ($installedPart -lt $recommendedPart) {
                return $true  # Vulnerable
            }
            elseif ($installedPart -gt $recommendedPart) {
                return $false  # Not vulnerable
            }
        }
        return $false  # Versions are equal - not vulnerable
    }
    catch {
        Write-Warning "Version comparison failed for '$InstalledVersion' vs '$RecommendedVersion'"
        return $true  # Treat comparison failures as vulnerable
    }
}

# Initialize results tracking
$results = @()
$vulnerableIPs = @()

foreach ($ip in $targets) {
    Write-Host "`nConnecting to $ip as $Username..."
    Write-Host "Authorized uses only. All activity may be monitored and reported."

    $session = $null
    $currentResult = @{
        IP = $ip
        InstalledVersion = $null
        IsVulnerable = $false
    }

    try {
        # Create SSH session
        $sessionParams = @{
            ComputerName    = $ip
            Credential      = $cred
            AcceptKey       = $true
            ErrorAction     = 'Stop'
            ConnectionTimeout = 10
        }
        if ($KeyPath) {
            $sessionParams.KeyFile = $KeyPath
        }

        $session = New-SSHSession @sessionParams

        # Execute command
        $result = Invoke-SSHCommand -SSHSession $session -Command $Command -ErrorAction Stop

        Write-Host "Last login: $(Get-Date -Format 'ddd MMM d HH:mm:ss yyyy')"
        Write-Host "[$Username@$ip]`$ $Command"

        if ($result.ExitStatus -eq 0) {
            $output = $result.Output.Trim()
            Write-Host $output
            $currentResult.InstalledVersion = $output
            
            # Check if version is vulnerable
            if ($output -and $output -notmatch "not installed|not found|No packages found") {
                $isVulnerable = Compare-RPMVersions -InstalledVersion $output -RecommendedVersion $RecommendedVersion
                $currentResult.IsVulnerable = $isVulnerable
                
                if ($isVulnerable) {
                    $vulnerableIPs += $ip
                }
            }
        }
        else {
            Write-Host "Command failed (Exit Code: $($result.ExitStatus))" -ForegroundColor Red
            Write-Host "Error: $($result.Error)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Connection Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if ($session) { $session | Remove-SSHSession | Out-Null }
    }
    
    $results += New-Object PSObject -Property $currentResult
}

# Display vulnerable servers summary
if ($vulnerableIPs.Count -gt 0) {
    Write-Host "`n" + "="*60 -ForegroundColor Red
    Write-Host "VULNERABLE SERVERS FOUND - REQUIRES IMMEDIATE ATTENTION" -ForegroundColor Red
    Write-Host "="*60 -ForegroundColor Red
    Write-Host "Recommended Version: $RecommendedVersion" -ForegroundColor Yellow
    Write-Host "`nThe following servers have vulnerable versions:" -ForegroundColor Red
    
    foreach ($vulnIP in $vulnerableIPs) {
        $vulnVersion = ($results | Where-Object { $_.IP -eq $vulnIP }).InstalledVersion
        Write-Host "  $vulnIP - $vulnVersion" -ForegroundColor Red
    }
    
    Write-Host "`nTotal Vulnerable Servers: $($vulnerableIPs.Count)" -ForegroundColor Red
}
else {
    Write-Host "`n" + "="*60 -ForegroundColor Green
    Write-Host "SCAN COMPLETED - NO VULNERABLE SERVERS FOUND" -ForegroundColor Green
    Write-Host "="*60 -ForegroundColor Green
}

Write-Host "`nOperation completed. Checked $($targets.Count) hosts." -ForegroundColor Green

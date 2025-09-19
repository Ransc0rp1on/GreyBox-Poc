param(
    [Parameter(Mandatory=$true)]
    [string]$IPs,
    [Parameter(Mandatory=$true)]
    [string]$Username,
    [Parameter(Mandatory=$true)]
    [string]$Command,
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

$targets = $IPs -split '[, ]+' | Where-Object { $_ }

foreach ($ip in $targets) {
    Write-Host "`nConnecting to $ip as $Username..."
    Write-Host "Authorized uses only. All activity may be monitored and reported."

    try {
        # Authentication handling
        if ($KeyPath) {
            # Key-based authentication
            if (-not (Test-Path $KeyPath)) {
                Write-Error "Key file not found at: $KeyPath"
                continue
            }
            $session = New-SSHSession -ComputerName $ip -Username $Username -KeyFile $KeyPath -AcceptKey -ErrorAction Stop
        }
        else {
            # Password-based authentication
            $cred = Get-Credential -UserName $Username -Message "Enter SSH Password"
            $session = New-SSHSession -ComputerName $ip -Credential $cred -AcceptKey -ErrorAction Stop
        }

        # Execute command
        $result = Invoke-SSHCommand -SSHSession $session -Command $Command -ErrorAction Stop

        Write-Host "Last login: $(Get-Date -Format 'ddd MMM d HH:mm:ss yyyy')"
        Write-Host "[$Username@$ip]`$ $Command"

        if ($result.ExitStatus -eq 0) {
            Write-Host $result.Output
        }
        else {
            Write-Host "Command failed (Exit Code: $($result.ExitStatus))" -ForegroundColor Red
            Write-Host "Error: $($result.Error)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "SSH Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if ($session) { $session | Remove-SSHSession | Out-Null }
    }
}

Write-Host "`nOperation completed. Checked $($targets.Count) hosts." -ForegroundColor Green

These scripts provide an automated way to verify package versions across multiple servers against Nessus vulnerability scan results. They help security teams quickly identify systems that require patching by comparing installed package versions with recommended secure versions.

# 🎯 Use Cases
Primary Use Case: Nessus Vulnerability Verification
Scenario: After running Nessus vulnerability scans, security teams need to verify which servers actually have vulnerable packages installed

Challenge: Manually checking dozens or hundreds of servers is time-consuming and error-prone

Solution: These scripts automate the verification process across all affected servers

PowerShell Version
```
# Basic usage
.\GB-Verification.ps1 -IPs "192.168.1.10,192.168.1.11" -Username "vapt-scan-user" -Command "rpm -q cloud-init" -RecommendedVersion "cloud-init-23.4-19.el9_5.6.noarch" -PackageName "cloud-init"
```
# Using IP list file
```
.\GB-Verification.ps1 -IPs "servers.txt" -Username "vapt-scan-user" -Command "rpm -q cloud-init" -RecommendedVersion "cloud-init-23.4-19.el9_5.6.noarch" -PackageName "cloud-init"
```
# Key-based authentication
```
.\GB-Verification.ps1 -IPs "192.168.1.10" -Username "vapt-scan-user" -Command "rpm -q cloud-init" -KeyPath "C:\ssh\key.pem" -RecommendedVersion "cloud-init-23.4-19.el9_5.6.noarch" -PackageName "cloud-init"
```
Bash Version
```
# Basic usage
./nessus-verify.sh --ips "192.168.1.10,192.168.1.11" --username "vapt-scan-user" --command "rpm -q cloud-init" --recommended-version "cloud-init-23.4-19.el9_5.6.noarch"
```
```
# Using IP list file
./nessus-verify.sh --ips "servers.txt" --username "vapt-scan-user" --command "rpm -q cloud-init" --recommended-version "cloud-init-23.4-19.el9_5.6.noarch"
```
```
# Only show vulnerable servers
./nessus-verify.sh --ips "192.168.1.10,192.168.1.11" --username "vapt-scan-user" --command "rpm -q cloud-init" --recommended-version "cloud-init-23.4-19.el9_5.6.noarch" --show-vulnerable-only
```
# 📈 Output Examples
Normal Output
```
Connecting to 192.168.1.10 as vapt-scan-user...
Authorized uses only. All activity may be monitored and reported.
Last login: Wed Aug  6 16:45:22 2025
[vapt-scan-user@192.168.1.10]$ rpm -q cloud-init
cloud-init-22.1-15.el9_4.1.noarch
```
Vulnerability Summary
```
============================================================
VULNERABLE SERVERS FOUND: 2/5
============================================================
The following servers have vulnerable versions:
  192.168.1.10 - cloud-init-22.1-15.el9_4.1.noarch
  192.168.1.12 - cloud-init-21.4-8.el9_3.2.noarch
============================================================
```

# 🛠️ Installation
PowerShell Prerequisites
```
# Install Posh-SSH module (automatically handled by script)
Install-Module Posh-SSH -Scope CurrentUser -Force
```
Bash Prerequisites
```
# Ensure SSH client is available (usually pre-installed)
ssh -V
```


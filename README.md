# LDAP Collector Script

## 📌 Overview
This PowerShell script collects Active Directory user and computer objects from specified domains and forests, then streams the data to a remote collector via TCP. It supports both encrypted (TLS) and unencrypted connections.

## 📂 Data Collection Features
Users: Harvests 40+ attributes including account status, group membership, and personal data
> TO change modify *@Properties* fields

 - Computers: Gathers system info, OS details, and network configurations

 - Flexible Filtering: Domain/forest level targeting with DC specification

 - PII Protection: Automatic hashing of sensitive fields

 - Using *lastLogonTImestamp* for sorting and optimizing getting data

## 🚀 Quick Start
1. Basic Usage:
```powershell
.\LDAPHarvest.ps1 -CollectorAddress 192.168.1.100 -CollectorPort 6000 -MaxEPS 250
```
2. Advanced Example:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\LDAPHarvest.ps1 `
    -CollectorAddress collector.example.com `
    -CollectorPort 6000 `
    -MaxEPS 500 `
    -AdditionalDC "dc2.corp.example.com","dc3.corp.example.com" `
    -Credential (Get-Credential) `
    -DebugMode `
    -ShowPII `
    -ForceUnencrypted
```

## 🔒 Data Protection (Personally Identifiable Information)
When -ShowPII is NOT specified:

- Hashes sensitive fields using SHA256

- Uses domain name as salt for consistent hashing

- Protects: emails, phone numbers, names, addresses...

## 📊 Output Format
JSON objects with these fields:

```json
{
  "source": "UserHarvest|ComputersHarvest",
  "domainName": "domain.forest.com",
  "forest": "forest.com",
  "whenCreated": "ISO8601",
  "lastLogon": "ISO8601",
  "enabled": true/false
  ***
}
```
## LDAP-Harvest Troubleshooting Guide

### Common Issues and Solutions

#### 1. ActiveDirectory Module Not Found

**Error:**
```
Import-Module : The specified module 'ActiveDirectory' was not loaded because no valid module file was found in any module directory.
```

**Solution:**

1. Check if module is available:
```powershell
Get-Module -ListAvailable ActiveDirectory
```

2. Install the required module using one of these methods:

For Windows 10/11:
```powershell
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
```

For Windows Server:
```powershell
Install-WindowsFeature RSAT-AD-PowerShell
```

#### 2. Network Problems

- **Firewall blocking ports** (typically 389/LDAP, 636/LDAPS, 88/Kerberos)
- **DNS issues** (domain resolves but individual servers don't)

**Diagnostics:**
```powershell
Test-NetConnection "YOUR_DOMAIN_CONTROLLER" -Port 389
Test-NetConnection "YOUR_DOMAIN_CONTROLLER" -Port 636
```

#### 3. Domain Controller Issues

- Older DCs that don't support modern queries
- DCs in another forest without trust relationships
- Domain exists in global catalog but its DCs are offline
- Domain is a "stub domain" or "trust domain" without its own DCs

**Diagnostics:**
```powershell
nltest /dclist:YOURDOMAIN
Get-ADDomainController -Filter *
```

#### 4. Authentication Problems

- Invalid credentials
- Insufficient permissions (requires at least Domain Users)
- No rights to read AD attributes
- Constrained delegation limitations

**Diagnostics:**
```powershell
# Test basic authentication
$cred = Get-Credential
Test-ADAuthentication -Credential $cred
```

#### 5. SSL/TLS Connection Failures

**Symptoms:**
- SSL handshake errors
- Fallback to unencrypted TCP not working

**Solutions:**

1. Force unencrypted connection:
```powershell
CollectorSocket -CollectorAddress "server" -CollectorPort 636 -ForceUnencrypted
```

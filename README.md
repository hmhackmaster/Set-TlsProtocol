# Set-TlsProtocols

A PowerShell script to manage **TLS/SSL protocols** on Windows 10, Windows 11, and Windows Server (2016, 2019, 2022).  
By default, it applies a **secure baseline**: disables SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 and enables TLS 1.2.  
Supports auditing, backup/restore, and optional .NET strong crypto defaults.

## Features
- Enable or disable specific protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2)
- Apply secure baseline with `-Secure`
- Backup current settings as JSON and restore later
- `-ReportOnly` mode to audit current state
- Optional .NET strong crypto and default secure protocol registry settings
- Supports `-WhatIf` and `-Confirm` for safe testing

## Requirements
- Windows 10, Windows 11, or Windows Server 2016/2019/2022  
- PowerShell 5.1  
- Run as **Administrator**  
- Reboot required for SCHANNEL changes to take effect  

## Usage
```powershell
# Report only (no changes)
.\Set-TlsProtocols.ps1 -ReportOnly

# Apply secure baseline and create a backup
.\Set-TlsProtocols.ps1 -Secure -Backup

# Restore from a backup JSON
.\Set-TlsProtocols.ps1 -Restore -From "C:\ProgramData\TlsToggle\backup-YYYY-MM-DDTHHMMSS.json"

# Enable only TLS 1.2 for Server-side
.\Set-TlsProtocols.ps1 -Enable "TLS 1.2" -Disable "TLS 1.0","TLS 1.1" -Scope Server -Backup
⚠️ Always test in a non-production environment before broad deployment. Legacy protocols are intentionally disabled for security.

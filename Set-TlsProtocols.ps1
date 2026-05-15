<#
.SYNOPSIS
  Manage SCHANNEL TLS/SSL protocol enablement on Windows with backup/restore and reporting.

.DESCRIPTION
  Enables/disables SSL 2.0/3.0, TLS 1.0/1.1/1.2 under:
  HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\<Proto>\<Server|Client>
  Presents a report, supports -WhatIf/-Confirm, and can back up/restore settings as JSON.

.PARAMETER Secure
  Apply secure baseline: Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1; Enable TLS 1.2.

.PARAMETER Enable
  One or more protocol names to enable (e.g. "TLS 1.2").

.PARAMETER Disable
  One or more protocol names to disable (e.g. "TLS 1.0","TLS 1.1").

.PARAMETER Scope
  'Server', 'Client', or 'Both' (default Both).

.PARAMETER Backup
  Save current SCHANNEL protocol settings to a JSON file before changes.

.PARAMETER BackupPath
  Directory for backups. Default: %ProgramData%\TlsToggle

.PARAMETER Restore
  Restore settings from a prior backup JSON file (use -From).

.PARAMETER From
  Path to backup JSON for -Restore.

.PARAMETER EnableDotNetStrongCrypto
  Sets .NET 4.x SchUseStrongCrypto/SystemDefaultTlsVersions and DefaultSecureProtocols (TLS1.2).

.PARAMETER ReportOnly
  Print current protocol states and exit (no changes).

.NOTES
  - Run as Administrator.
  - Reboot required for SCHANNEL protocol changes to take effect.
  - TLS 1.3 is not managed by these registry keys (and isn’t supported on Server 2019).
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [switch]$Secure,
  [ValidateSet("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")]
  [string[]]$Enable,
  [ValidateSet("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")]
  [string[]]$Disable,
  [ValidateSet("Server","Client","Both")]
  [string]$Scope = "Both",
  [switch]$Backup,
  [string]$BackupPath = "$env:ProgramData\TlsToggle",
  [switch]$Restore,
  [string]$From,
  [switch]$EnableDotNetStrongCrypto,
  [switch]$ReportOnly
)

# ------------------ Helpers ------------------

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Access denied. Please run PowerShell as Administrator."
  }
}

$ProtocolNames = @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2", "TLS 1.3")
$Root = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

function Get-ProtoKeyPaths([string]$name,[string]$scope){
  $paths = @()
  if ($scope -eq "Server" -or $scope -eq "Both") { $paths += Join-Path "$Root\$name" "Server" }
  if ($scope -eq "Client" -or $scope -eq "Both") { $paths += Join-Path "$Root\$name" "Client" }
  return $paths
}

function Ensure-Key([string]$path){
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
}

function Get-ProtocolState([string]$name,[string]$scope){
  $paths = Get-ProtoKeyPaths -name $name -scope $scope
  $result = @()
  foreach($p in $paths){
    $prop = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
    $enabled = if ($prop -and ($prop.PSObject.Properties.Name -contains 'Enabled')) { [int]$prop.Enabled } else { $null }
    $dbd     = if ($prop -and ($prop.PSObject.Properties.Name -contains 'DisabledByDefault')) { [int]$prop.DisabledByDefault } else { $null }

    # Effective: null-safe
    $effective = if (-not $TLS13Support -and $name -eq "TLS 1.3") {
      'Unsupported'
    } elseif ($enabled -eq 1 -and $dbd -eq 0) {
      'Enabled'
    } elseif ($enabled -eq 0 -and $dbd -eq 1) {
      'Disabled'
    } elseif ($enabled -eq 0 -and $dbd -eq $null) {
      'Disabled'
    } else {
      'Undefined'
    }

    $result += [pscustomobject]@{
      Protocol          = $name
      Path              = $p
      Enabled           = $enabled
      DisabledByDefault = $dbd
      Effective         = $effective
    }
  }
  return $result
}

function Set-Protocol([string]$name,[bool]$enable,[string]$scope){
  $paths = Get-ProtoKeyPaths -name $name -scope $scope
  foreach($p in $paths){
    Ensure-Key $p
    $target = if($enable){"enable"}else{"disable"}
    if ($PSCmdlet.ShouldProcess("$name @ $p", "Set to $target")) {
      try {
        # Enabled:1 + DisabledByDefault:0 => enabled
        # Enabled:0 + DisabledByDefault:1 => disabled
        $en = [int]($enable)
        $dbd = [int](-not $enable)
        New-ItemProperty -Path $p -Name 'Enabled' -Value $en -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $p -Name 'DisabledByDefault' -Value $dbd -PropertyType DWord -Force | Out-Null
      } catch {
        Write-Error "Failed to set $name at $p : $($_.Exception.Message)"
      }
    }
  }
}

function Save-Backup([string]$destDir){
  if (-not (Test-Path $destDir)){ New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
  $stamp = (Get-Date).ToString("yyyy-MM-ddTHHmmss")
  $file  = Join-Path $destDir "backup-$stamp.json"
  $snap = @()
  foreach($n in $ProtocolNames){
    $snap += Get-ProtocolState -name $n -scope "Both"
  }
  $snap | ConvertTo-Json | Set-Content -Path $file -Encoding UTF8
  Write-Host "Backup saved to: $file"
  return $file
}

function Restore-FromFile([string]$file){
  if (-not (Test-Path $file)) { throw "Backup file not found: $file" }
  $data = Get-Content -Path $file -Raw | ConvertFrom-Json
  foreach($row in $data){
    $path = $row.Path
    Ensure-Key $path
    if ($PSCmdlet.ShouldProcess($path,"Restore Enabled/DisabledByDefault from backup")) {
      if ($null -ne $row.Enabled)            { New-ItemProperty -Path $path -Name 'Enabled' -Value ([int]$row.Enabled) -PropertyType DWord -Force | Out-Null }
      if ($null -ne $row.DisabledByDefault)   { New-ItemProperty -Path $path -Name 'DisabledByDefault' -Value ([int]$row.DisabledByDefault) -PropertyType DWord -Force | Out-Null }
    }
  }
}

function Write-Report([string]$title){
  Write-Host "`n==== $title ====" -ForegroundColor Cyan
  $table = foreach($n in $ProtocolNames){ Get-ProtocolState -name $n -scope "Both" }
  $table | Sort-Object Protocol,Path | Select-Object Protocol, @{Name = 'Path'; Expression = {$_.Path -replace ".*SCHANNEL"}}, Enabled, DisabledByDefault, Effective | Format-Table -AutoSize
}

function Set-DotNetStrongCrypto {
  # .NET 4.x defaults: strong crypto + use OS default TLS versions
  $base    = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
  $baseWow = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
  $ieBase  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
  $winHttp = Join-Path $ieBase "WinHttp"

  foreach($b in @($base,$baseWow)){
    if ($PSCmdlet.ShouldProcess($b,"Enable SchUseStrongCrypto=1; SystemDefaultTlsVersions=1")){
      New-Item -Path $b -Force | Out-Null
      New-ItemProperty -Path $b -Name "SchUseStrongCrypto" -Value 1 -PropertyType DWord -Force | Out-Null
      New-ItemProperty -Path $b -Name "SystemDefaultTlsVersions" -Value 1 -PropertyType DWord -Force | Out-Null
    }
  }

  if ($PSCmdlet.ShouldProcess($ieBase,"Set DefaultSecureProtocols (TLS 1.2)")){
    # TLS 1.2 bit = 0x00000800
    New-Item -Path $ieBase -Force | Out-Null
    New-ItemProperty -Path $ieBase -Name "DefaultSecureProtocols" -Value 0x00000800 -PropertyType DWord -Force | Out-Null
    New-Item -Path $winHttp -Force | Out-Null
    New-ItemProperty -Path $winHttp -Name "DefaultSecureProtocols" -Value 0x00000800 -PropertyType DWord -Force | Out-Null
  }

  Write-Host "Enabled .NET strong crypto and default secure protocols."
}

# ------------------ Main ------------------

Test-Admin

$WinVerInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Write-Host "Detected OS: $($WinVerInfo.ProductName); Build: $($WinVerInfo.CurrentBuildNumber)"

if ([int]$WinVerInfo.CurrentBuildNumber -ge 20348) {
  Write-Verbose "OS build 20348 (Server 2022) and greater supports TLS 1.3"
  $TLS13Support = $True
}

Write-Report "Current SCHANNEL Protocol State"

if ($ReportOnly) { return }

if ($Restore){
  if (-not $From){ throw "Use -From <backup.json> with -Restore." }
  Restore-FromFile -file $From
  Write-Report "State After Restore"
  Write-Host "`nReboot required for changes to take effect."
  return
}

if ($Backup){ $null = Save-Backup -destDir $BackupPath }

# Resolve actions
$toEnable = @()
$toDisable = @()

if ($Secure){
  $toDisable += "SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1"
  $toEnable  += "TLS 1.2"
  if($TLS13Support) {
    $toEnable  += "TLS 1.3"
  }
}

if ($Enable){  $toEnable  += $Enable }
if ($Disable){ $toDisable += $Disable }

# Sanity: dedupe; guard against same protocol in both lists
$toEnable  = $toEnable  | Where-Object { $_ } | Select-Object -Unique
$toDisable = $toDisable | Where-Object { $_ } | Select-Object -Unique
$clash = $toEnable | Where-Object { $toDisable -contains $_ }
if ($clash){ throw "Same protocol in -Enable and -Disable: $($clash -join ', ')" }

# Apply changes
foreach($n in $toEnable){
  if ($ProtocolNames -notcontains $n){ Write-Warning "Unknown protocol '$n' (skipped)"; continue }
  Set-Protocol -name $n -enable:$true -scope $Scope
}
foreach($n in $toDisable){
  if ($ProtocolNames -notcontains $n){ Write-Warning "Unknown protocol '$n' (skipped)"; continue }
  Set-Protocol -name $n -enable:$false -scope $Scope
}

if ($EnableDotNetStrongCrypto){ Set-DotNetStrongCrypto }

Write-Report "State After Changes"
Write-Host "`nReboot required for SCHANNEL protocol changes to take effect."


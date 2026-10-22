<#
.SYNOPSIS
    Read-only hardening fact collector for Windows Server 2016+ and Windows 10/11.

.DESCRIPTION
    Gathers the configuration facts evaluated by hardening-auditor (password and lockout policy,
    SMB, LLMNR/NetBIOS, NTLM, LSA protection, firewall, RDP, audit policy, PowerShell, services,
    BitLocker, updates) and writes them to a single JSON file.

    The script never changes the system: it only reads the registry, CIM classes and the output
    of secedit /export and auditpol /backup (written to a temporary file, then deleted). It needs
    no internet access and no module beyond those shipped with Windows PowerShell 5.1.

    Run it from an elevated prompt: without administrator rights, the security policy, audit
    policy and BitLocker facts cannot be read and the related controls are reported as unknown.

.PARAMETER OutputPath
    Where to write the JSON file. Defaults to .\<COMPUTERNAME>-facts.json.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-HardeningCollector.ps1 -OutputPath C:\Temp\srv01.json
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath ('{0}-facts.json' -f $env:COMPUTERNAME))
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$CollectorVersion = '1.0.0'
$script:Facts = [ordered]@{}
$script:Warnings = @()

function Add-Fact {
    param([Parameter(Mandatory)][string]$Name, [AllowNull()]$Value)
    $script:Facts[$Name] = $Value
}

function Add-CollectorWarning {
    param([Parameter(Mandatory)][string]$Message)
    $script:Warnings += $Message
    Write-Verbose $Message
}

function Invoke-Section {
    # Runs one block of collection; a failure is recorded as a warning and never stops the script.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Body)
    try {
        & $Body
    } catch {
        Add-CollectorWarning ('{0}: {1}' -f $Name, $_.Exception.Message)
    }
}

function Get-RegistryValue {
    # Returns the value, or $null when the key or the value does not exist.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

function ConvertTo-IntOrNull {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    $number = 0
    if ([int]::TryParse("$Value", [ref]$number)) { return $number }
    return $null
}

# --------------------------------------------------------------------------- host and privileges
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
# High Mandatory Level SID: present only in an elevated token, whatever the display language.
$elevated = [bool]((whoami.exe /groups) -match 'S-1-16-12288')
if (-not $elevated) {
    Add-CollectorWarning 'Not running elevated: security policy, audit policy and BitLocker facts are not collected.'
}

$productType = switch ([int]$os.ProductType) { 1 { 'workstation' } 2 { 'domain_controller' } default { 'server' } }
Add-Fact 'os.product_type' $productType
Add-Fact 'os.domain_joined' ([bool]$computer.PartOfDomain)
Add-Fact 'os.build' ([string]$os.BuildNumber)

# --------------------------------------------------------------------------- local security policy
Invoke-Section 'Security policy (secedit)' {
    if (-not $elevated) { return }
    $temp = Join-Path -Path $env:TEMP -ChildPath ('ha-secpol-{0}.inf' -f [guid]::NewGuid())
    try {
        $null = secedit.exe /export /cfg $temp /areas SECURITYPOLICY /quiet
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $temp)) { throw "secedit exited with code $LASTEXITCODE" }
        $policy = @{}
        foreach ($line in Get-Content -LiteralPath $temp) {
            if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$') { $policy[$Matches[1]] = $Matches[2] }
        }
    } finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
    $map = [ordered]@{
        'policy.password.min_length'            = 'MinimumPasswordLength'
        'policy.password.complexity'            = 'PasswordComplexity'
        'policy.password.history'               = 'PasswordHistorySize'
        'policy.password.min_age_days'          = 'MinimumPasswordAge'
        'policy.password.max_age_days'          = 'MaximumPasswordAge'
        'policy.password.reversible_encryption' = 'ClearTextPassword'
        'policy.lockout.threshold'              = 'LockoutBadCount'
        'policy.lockout.duration_minutes'       = 'LockoutDuration'
        'policy.lockout.reset_minutes'          = 'ResetLockoutCount'
        'policy.accounts.guest_enabled'         = 'EnableGuestAccount'
        'policy.accounts.admin_enabled'         = 'EnableAdminAccount'
    }
    foreach ($fact in $map.Keys) {
        if ($policy.ContainsKey($map[$fact])) { Add-Fact $fact (ConvertTo-IntOrNull $policy[$map[$fact]]) }
    }
    # Without a lockout threshold Windows does not write the duration and reset values.
    if ($policy['LockoutBadCount'] -eq '0') {
        foreach ($fact in 'policy.lockout.duration_minutes', 'policy.lockout.reset_minutes') {
            if (-not $script:Facts.Contains($fact)) { Add-Fact $fact 0 }
        }
    }
}

# --------------------------------------------------------------------------- local accounts
Invoke-Section 'Local administrators' {
    if ($productType -eq 'domain_controller') { return }
    $members = @()
    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [string]$_.Name })
    } catch {
        # Get-LocalGroupMember fails on orphaned SIDs; fall back to the WinNT provider listing.
        $group = Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
        $members = @(Get-CimAssociatedInstance -InputObject $group -ResultClassName Win32_Account |
            ForEach-Object { '{0}\{1}' -f $_.Domain, $_.Name })
    }
    Add-Fact 'accounts.local_admins' @($members | Sort-Object)
}

Invoke-Section 'LAPS' {
    $windowsLaps = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory'
    if ($null -eq $windowsLaps) {
        $windowsLaps = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' 'BackupDirectory'
    }
    Add-Fact 'laps.windows.backup_directory' (ConvertTo-IntOrNull $windowsLaps)
    Add-Fact 'laps.legacy.enabled' (ConvertTo-IntOrNull (Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'))
}

# --------------------------------------------------------------------------- SMB, name resolution
Invoke-Section 'SMB' {
    $server = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $client = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    Add-Fact 'smb.server.require_signing' (ConvertTo-IntOrNull (Get-RegistryValue $server 'RequireSecuritySignature'))
    Add-Fact 'smb.client.require_signing' (ConvertTo-IntOrNull (Get-RegistryValue $client 'RequireSecuritySignature'))

    $smb1 = $null
    try {
        $smb1 = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol
    } catch {
        # Absent value means the protocol follows the installed feature: treat as enabled unless 0.
        $value = Get-RegistryValue $server 'SMB1'
        if ($null -ne $value) { $smb1 = ([int]$value -ne 0) }
    }
    Add-Fact 'smb.server.smb1_enabled' $smb1

    $driverKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
    $driverPresent = Test-Path -LiteralPath $driverKey
    Add-Fact 'smb.client.smb1_driver_present' $driverPresent
    if ($driverPresent) { Add-Fact 'smb.client.smb1_driver_start' (ConvertTo-IntOrNull (Get-RegistryValue $driverKey 'Start')) }
}

Invoke-Section 'LLMNR and NetBIOS' {
    Add-Fact 'network.llmnr.enable_multicast' (ConvertTo-IntOrNull (Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'))
    # TcpipNetbiosOptions: 0 = from DHCP (enabled unless the DHCP server says otherwise), 1 = enabled, 2 = disabled.
    $adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' |
        Where-Object { $_.TcpipNetbiosOptions -ne 2 } | ForEach-Object { [string]$_.Description })
    Add-Fact 'network.netbios.enabled_adapters' @($adapters)
}

# --------------------------------------------------------------------------- LSA, NTLM, credentials
Invoke-Section 'LSA' {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Add-Fact 'lsa.lm_compatibility_level' (ConvertTo-IntOrNull (Get-RegistryValue $lsa 'LmCompatibilityLevel'))
    Add-Fact 'lsa.no_lm_hash' (ConvertTo-IntOrNull (Get-RegistryValue $lsa 'NoLMHash'))
    Add-Fact 'lsa.restrict_anonymous' (ConvertTo-IntOrNull (Get-RegistryValue $lsa 'RestrictAnonymous'))
    Add-Fact 'lsa.restrict_anonymous_sam' (ConvertTo-IntOrNull (Get-RegistryValue $lsa 'RestrictAnonymousSAM'))
    Add-Fact 'lsa.everyone_includes_anonymous' (ConvertTo-IntOrNull (Get-RegistryValue $lsa 'EveryoneIncludesAnonymous'))
    Add-Fact 'lsa.run_as_ppl' (ConvertTo-IntOrNull (Get-RegistryValue $lsa 'RunAsPPL'))
    Add-Fact 'lsa.sce_no_apply_legacy_audit_policy' (ConvertTo-IntOrNull (Get-RegistryValue $lsa 'SCENoApplyLegacyAuditPolicy'))
    Add-Fact 'wdigest.use_logon_credential' (ConvertTo-IntOrNull (Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'))
}

Invoke-Section 'Credential Guard' {
    $guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
    # SecurityServicesRunning contains 1 when Credential Guard is running.
    Add-Fact 'deviceguard.credential_guard_running' ([bool](@($guard.SecurityServicesRunning) -contains 1))
    Add-Fact 'deviceguard.vbs_status' (ConvertTo-IntOrNull $guard.VirtualizationBasedSecurityStatus)
}

Invoke-Section 'UAC' {
    $system = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Add-Fact 'uac.enable_lua' (ConvertTo-IntOrNull (Get-RegistryValue $system 'EnableLUA'))
    Add-Fact 'uac.local_account_token_filter_policy' (ConvertTo-IntOrNull (Get-RegistryValue $system 'LocalAccountTokenFilterPolicy'))
    Add-Fact 'audit.process_creation_cmdline' (ConvertTo-IntOrNull (Get-RegistryValue "$system\Audit" 'ProcessCreationIncludeCmdLine_Enabled'))
}

# --------------------------------------------------------------------------- firewall and RDP
Invoke-Section 'Firewall' {
    # ActiveStore is the effective configuration, local settings merged with Group Policy.
    foreach ($fwProfile in Get-NetFirewallProfile -PolicyStore ActiveStore) {
        $name = ([string]$fwProfile.Name).ToLowerInvariant()
        Add-Fact "firewall.$name.enabled" ([string]$fwProfile.Enabled -eq 'True')
        Add-Fact "firewall.$name.default_inbound" ([string]$fwProfile.DefaultInboundAction).ToLowerInvariant()
    }
}

Invoke-Section 'Remote Desktop' {
    $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $deny = Get-RegistryValue $policy 'fDenyTSConnections'
    if ($null -eq $deny) { $deny = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' }
    Add-Fact 'rdp.enabled' ($null -ne $deny -and [int]$deny -eq 0)
    $nla = Get-RegistryValue $policy 'UserAuthentication'
    if ($null -eq $nla) { $nla = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' }
    Add-Fact 'rdp.nla_required' ($null -ne $nla -and [int]$nla -eq 1)
}

# --------------------------------------------------------------------------- audit and logging
Invoke-Section 'Audit policy (auditpol)' {
    if (-not $elevated) { return }
    # Subcategory GUIDs and numeric settings keep the parsing independent of the display language.
    $subcategories = @{
        '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'credential_validation'
        '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'logon'
        '{0CCE921B-69AE-11D9-BED3-505054503030}' = 'special_logon'
        '{0CCE9217-69AE-11D9-BED3-505054503030}' = 'account_lockout'
        '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'process_creation'
        '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'user_account_management'
        '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'security_group_management'
        '{0CCE922F-69AE-11D9-BED3-505054503030}' = 'audit_policy_change'
    }
    $settings = @{ 0 = 'no_auditing'; 1 = 'success'; 2 = 'failure'; 3 = 'success_and_failure' }
    $temp = Join-Path -Path $env:TEMP -ChildPath ('ha-auditpol-{0}.csv' -f [guid]::NewGuid())
    try {
        $null = auditpol.exe /backup /file:$temp
        if ($LASTEXITCODE -ne 0) { throw "auditpol exited with code $LASTEXITCODE" }
        $rows = Import-Csv -LiteralPath $temp
    } finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
    foreach ($guid in $subcategories.Keys) { Add-Fact "audit.$($subcategories[$guid])" 'no_auditing' }
    foreach ($row in $rows) {
        $guid = [string]$row.'Subcategory GUID'
        if ($subcategories.ContainsKey($guid)) {
            $value = ConvertTo-IntOrNull $row.'Setting Value'
            if ($null -ne $value -and $settings.ContainsKey($value)) { Add-Fact "audit.$($subcategories[$guid])" $settings[$value] }
        }
    }
}

Invoke-Section 'Security event log' {
    $size = $null
    try {
        $size = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
    } catch {
        $size = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize'
    }
    if ($null -ne $size) { Add-Fact 'eventlog.security.max_size_kb' ([int64]([int64]$size / 1024)) }
}

# --------------------------------------------------------------------------- PowerShell
Invoke-Section 'PowerShell' {
    Add-Fact 'powershell.scriptblock_logging' (ConvertTo-IntOrNull (Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'))
    Add-Fact 'powershell.language_mode' ([string]$ExecutionContext.SessionState.LanguageMode)
}

Invoke-Section 'PowerShell 2.0 engine' {
    if (-not $elevated) { return }
    $installed = $false
    if ($productType -eq 'workstation') {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue
        $installed = ($null -ne $feature -and [string]$feature.State -eq 'Enabled')
    } elseif (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $feature = Get-WindowsFeature -Name 'PowerShell-V2' -ErrorAction SilentlyContinue
        $installed = ($null -ne $feature -and [bool]$feature.Installed)
    } else {
        throw 'neither Get-WindowsOptionalFeature nor Get-WindowsFeature can be used'
    }
    Add-Fact 'powershell.v2_installed' $installed
}

# --------------------------------------------------------------------------- services, disk, updates
Invoke-Section 'Services' {
    $services = @(Get-CimInstance -ClassName Win32_Service -Property Name, StartMode, State)
    Add-Fact 'services.not_disabled' @($services | Where-Object { $_.StartMode -ne 'Disabled' } |
        ForEach-Object { ([string]$_.Name).ToLowerInvariant() } | Sort-Object)
    Add-Fact 'services.running' @($services | Where-Object { $_.State -eq 'Running' } |
        ForEach-Object { ([string]$_.Name).ToLowerInvariant() } | Sort-Object)
}

Invoke-Section 'BitLocker' {
    if (-not $elevated) { return }
    try {
        $volume = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'"
    } catch {
        # Windows Server without the BitLocker feature has no such namespace: the volume is not encrypted.
        if ([string]$_.Exception.NativeErrorCode -ne 'InvalidNamespace') { throw }
        Add-CollectorWarning 'BitLocker: the feature is not installed, the OS volume is reported as not encrypted.'
        Add-Fact 'bitlocker.os_volume.protection_on' $false
        return
    }
    if ($null -eq $volume) { Add-Fact 'bitlocker.os_volume.protection_on' $false; return }
    # ProtectionStatus: 0 = off, 1 = on, 2 = unknown (locked).
    Add-Fact 'bitlocker.os_volume.protection_on' ([int]$volume.ProtectionStatus -eq 1)
}

Invoke-Section 'Updates' {
    $last = Get-CimInstance -ClassName Win32_QuickFixEngineering |
        Where-Object { $null -ne $_.InstalledOn -and "$($_.InstalledOn)" -ne '' } |
        ForEach-Object { [datetime]$_.InstalledOn } |
        Sort-Object -Descending | Select-Object -First 1
    if ($null -ne $last) {
        Add-Fact 'updates.last_hotfix_date' $last.ToString('yyyy-MM-dd')
        Add-Fact 'updates.days_since_last_hotfix' ([int]((Get-Date) - $last).TotalDays)
    }
}

# --------------------------------------------------------------------------- output
$document = [ordered]@{
    schema_version = 1
    collector      = [ordered]@{ name = 'hardening-auditor-windows'; version = $CollectorVersion; powershell = $PSVersionTable.PSVersion.ToString() }
    host           = [ordered]@{
        hostname     = $env:COMPUTERNAME
        os_family    = 'windows'
        os_name      = [string]$os.Caption
        os_version   = [string]$os.Version
        collected_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        elevated     = $elevated
    }
    warnings       = @($script:Warnings)
    facts          = $script:Facts
}
$json = $document | ConvertTo-Json -Depth 6
$directory = Split-Path -Path $OutputPath -Parent
if ($directory -and -not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Path $directory }
Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
Write-Output ('Collected {0} facts ({1} warning(s)) into {2}' -f $script:Facts.Count, $script:Warnings.Count, $OutputPath)

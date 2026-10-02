# Opt-in, reversible ICMP error rules for this experimental Windows kernel.
[CmdletBinding()]
param(
    [ValidateSet('Show', 'Enable', 'Disable')][string]$Action = 'Show',
    [Parameter(Mandatory = $true)][string]$InterfaceAlias,
    [ValidateSet('Any', 'Domain', 'Private', 'Public')][string[]]$Profile = @('Any')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This script requires Windows.' }
$adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
if (@($adapter).Count -ne 1) { throw 'Specify exactly one outbound physical interface.' }
if ($adapter.InterfaceDescription -match 'Wintun|TAP|Tailscale') {
    throw 'Specify the physical DIRECT outbound interface, such as Wi-Fi or Ethernet.'
}
$InterfaceAlias = [string]$adapter.Name
$group = 'Mihomo experimental ICMP trace'
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InterfaceAlias.ToLowerInvariant())
    $suffix = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').Substring(0, 12)
} finally { $sha.Dispose() }
$name = 'Mihomo-ICMP-Trace-v4-' + $suffix
$existing = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
if ($null -ne $existing -and $existing.Group -ne $group) {
    throw 'An unrelated rule uses the same name; no changes were made.'
}
if ($Action -ne 'Show') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run PowerShell as administrator to change this rule.'
    }
}
if ($Action -eq 'Enable') {
    if ($null -ne $existing) { Remove-NetFirewallRule -Name $name }
    New-NetFirewallRule -Name $name -DisplayName ('Mihomo ICMP trace errors: ' + $InterfaceAlias) `
        -Group $group -Direction Inbound -Action Allow -Enabled True -Profile $Profile `
        -InterfaceAlias $InterfaceAlias -Protocol ICMPv4 -IcmpType @('3', '11', '12') `
        -Description 'Allows ICMP errors needed by raw DIRECT traceroute. Managed by set_icmp_trace_firewall.ps1.' |
        Select-Object Name, Enabled, Direction, Action, Profile
} elseif ($Action -eq 'Disable') {
    if ($null -ne $existing) { Remove-NetFirewallRule -Name $name }
    Write-Output ('Removed managed ICMP trace rule for ' + $InterfaceAlias)
} else {
    if ($null -eq $existing) { Write-Output ('No managed ICMP trace rule for ' + $InterfaceAlias) }
    else {
        $existing | Select-Object Name, Enabled, Direction, Action, Profile
        $existing | Get-NetFirewallPortFilter | Select-Object Protocol, IcmpType
        $existing | Get-NetFirewallInterfaceFilter | Select-Object InterfaceAlias
    }
}

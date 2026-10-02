# Public packets only: run the same reviewed kernel OFF/mixed/gvisor on one IP.
# A temporary physical-interface ICMP rule holds the local firewall condition
# constant. It never disables firewall profiles or changes default policies.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$KernelPath,
    [Parameter(Mandatory = $true)][string]$BestTracePath,
    [Parameter(Mandatory = $true)][ValidateSet('1.1.1.1', '8.8.8.8', '9.9.9.9', '223.5.5.5')][string]$Target,
    [string]$OutputDir = 'evidence',
    [ValidatePattern('^[0-9]+$')][string]$TestedRunId = '36913225840'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$expectedKernelHash = '6b01bb11de95bd51c10b7decb6a0c2a2ebe9f8d7147371a035b149bcc2d37383'
$ruleName = 'MihomoPublicICMP-' + $PID + '-' + [guid]::NewGuid().ToString('N')
$ruleAdded = $false
$validationExit = 1
$startedAt = [DateTime]::UtcNow
[void](New-Item -ItemType Directory -Path $OutputDir -Force)
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$runtimeDirectory = Join-Path $OutputDir 'runtime'

function Write-Json($Object, [string]$Path) {
    ConvertTo-Json -InputObject $Object -Depth 24 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Read-Environment {
    $result = [ordered]@{
        recorded_at = [DateTime]::UtcNow.ToString('o')
        runner_name = $env:RUNNER_NAME; runner_os = $env:RUNNER_OS; runner_arch = $env:RUNNER_ARCH
        image_os = $env:ImageOS; image_version = $env:ImageVersion
        requested_runner_image = $env:PUBLIC_RUNNER_IMAGE
        os_version = [Environment]::OSVersion.Version.ToString()
        powershell_version = $PSVersionTable.PSVersion.ToString()
        repository_commit = $env:GITHUB_SHA; workflow_run_id = $env:GITHUB_RUN_ID
        os = $null; nat = $null; public_identity = $null; firewall_profiles = @()
        limitations = @('Get-NetNat reports guest-configured NAT only; an empty result cannot exclude provider-side NAT.',
            'HTTPS public identity is a best-effort egress observation; it cannot identify which network device filters ICMP.')
    }
    try {
        $result.os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
    } catch { $result.os = [ordered]@{ error = $_.Exception.Message } }
    try {
        $result.nat = [ordered]@{ status = 'recorded'; entries = @(Get-NetNat -ErrorAction Stop |
            Select-Object Name, InternalIPInterfaceAddressPrefix, ExternalIPInterfaceAddressPrefix, Active); error = $null }
    } catch { $result.nat = [ordered]@{ status = 'unavailable'; entries = @(); error = $_.Exception.Message } }
    try {
        $identity = (Invoke-WebRequest 'https://api.ipify.org' -TimeoutSec 10).Content.Trim()
        $parsedAddress = $null
        if (-not [System.Net.IPAddress]::TryParse($identity, [ref]$parsedAddress)) { throw 'Identity response was not an IP address.' }
        $result.public_identity = [ordered]@{ status = 'observed'; address = $identity; endpoint = 'https://api.ipify.org'; error = $null }
    } catch { $result.public_identity = [ordered]@{ status = 'unavailable'; address = $null; endpoint = 'https://api.ipify.org'; error = $_.Exception.Message } }
    try { $result.firewall_profiles = @(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction) }
    catch { $result.firewall_profiles = @([ordered]@{ error = $_.Exception.Message }) }
    return $result
}

function Get-PhysicalExit([string]$Address) {
    $found = @(Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop)
    $indices = @($found | ForEach-Object { $_.InterfaceIndex } | Select-Object -Unique)
    foreach ($index in $indices) {
        $adapter = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object { $_.ifIndex -eq $index -and $_.Status -eq 'Up' } | Select-Object -First 1
        if ($null -ne $adapter -and $adapter.Status -eq 'Up') {
            return [ordered]@{ name = [string]$adapter.Name; index = [int]$index
                description = [string]$adapter.InterfaceDescription
                addresses = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 | ForEach-Object { $_.IPAddress }) }
        }
    }
    throw "No usable physical outbound adapter found for $Address before TUN startup."
}

function Invoke-PingPreflight([string]$Condition) {
    $rows = [System.Collections.Generic.List[object]]::new()
    $ping = [System.Net.NetworkInformation.Ping]::new()
    try {
        foreach ($attempt in 1..2) {
            try {
                $options = [System.Net.NetworkInformation.PingOptions]::new(128, $false)
                $payload = [System.Text.Encoding]::ASCII.GetBytes('public-icmp-preflight')
                $reply = $ping.Send($Target, 1500, $payload, $options)
                $rows.Add([ordered]@{ attempt = $attempt; ttl = 128; status = $reply.Status.ToString()
                    address = [string]$reply.Address; roundtrip_ms = $reply.RoundtripTime; error = $null })
            } catch { $rows.Add([ordered]@{ attempt = $attempt; ttl = 128; status = 'error'; error = $_.Exception.Message }) }
        }
    } finally { $ping.Dispose() }
    return [ordered]@{ target = $Target; firewall_condition = $Condition; observations = @($rows.ToArray()) }
}

function Invoke-TcpControls {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($port in @(443, 53)) {
        $client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $entry = [ordered]@{ target = $Target; port = $port; connected = $false; elapsed_ms = $null; local_endpoint = $null; error = $null }
        try {
            $task = $client.ConnectAsync($Target, $port)
            if (-not $task.Wait(5000)) { throw 'TCP connect timed out after 5000 ms.' }
            $entry.connected = $client.Connected
            $entry.local_endpoint = [string]$client.Client.LocalEndPoint
        } catch { $entry.error = $_.Exception.Message }
        finally { $watch.Stop(); $entry.elapsed_ms = $watch.ElapsedMilliseconds; $client.Dispose() }
        $rows.Add($entry)
    }
    return [ordered]@{ observations = @($rows.ToArray())
        interpretation = 'TCP reachability is an independent connectivity control; it does not prove that ICMP Echo or Time Exceeded is permitted.' }
}

$comparison = [ordered]@{
    status = 'blocked'; reason = 'Public comparison has not completed.'; target = $Target
    mode = 'real-public-icmp'; synthetic_packets = $false; tested_kernel_run_id = $TestedRunId
    expected_kernel_sha256 = $expectedKernelHash; actual_kernel_sha256 = $null
    started_at = $startedAt.ToString('o'); ended_at = $null; validation_exit_code = $null
    environment = $null; physical_exit = $null; preflight_default = $null; preflight_allowed = $null; tcp_controls = $null
    firewall = [ordered]@{ condition = 'physical-interface temporary inbound ICMPv4 allow'
        rule = $null; added = $false; removed = $false; cleanup_error = $null; default_policies_changed = $false }
    scenarios = @(); validation_summary_path = (Join-Path $runtimeDirectory 'summary.json'); fatal_error = $null
    limitations = @('A public all-star baseline or missing endpoint is inconclusive, never a pass.',
        'Runner network constraints require measured evidence; these observations alone do not identify a specific NAT or filtering device.',
        'Each target receives an OFF, mixed, and gvisor comparison on this runner image only.')
}
try {
    if (Test-Path -LiteralPath $runtimeDirectory) {
        throw 'Use a new OutputDir: an existing runtime directory could mix current and previous evidence.'
    }
    $KernelPath = (Resolve-Path -LiteralPath $KernelPath).Path
    $BestTracePath = (Resolve-Path -LiteralPath $BestTracePath).Path
    $comparison.actual_kernel_sha256 = (Get-FileHash -LiteralPath $KernelPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($comparison.actual_kernel_sha256 -ne $expectedKernelHash) { throw 'Downloaded kernel differs from the reviewed tested artifact; refusing execution.' }
    $comparison.environment = Read-Environment
    Write-Json $comparison.environment (Join-Path $OutputDir 'public-environment.json')
    $comparison.physical_exit = Get-PhysicalExit $Target
    $comparison.preflight_default = Invoke-PingPreflight 'default firewall before diagnostic rule'
    Write-Json $comparison.preflight_default (Join-Path $OutputDir 'preflight-default.json')
    $comparison.tcp_controls = Invoke-TcpControls
    Write-Json $comparison.tcp_controls (Join-Path $OutputDir 'tcp-controls.json')

    $rule = New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Inbound -Action Allow `
        -Enabled True -Profile Any -Protocol ICMPv4 -IcmpType @('0', '3', '11', '12') `
        -Program Any -RemoteAddress Any -InterfaceAlias $comparison.physical_exit.name -ErrorAction Stop
    $ruleAdded = $true
    $comparison.firewall.added = $true
    $comparison.firewall.rule = [ordered]@{ name = [string]$rule.Name; direction = 'Inbound'; action = 'Allow'
        profile = 'Any'; protocol = 'ICMPv4'; types = @('0', '3', '11', '12'); program = 'Any'; remote_address = 'Any'
        interface_alias = $comparison.physical_exit.name; interface_index = $comparison.physical_exit.index }
    Write-Json $comparison.firewall (Join-Path $OutputDir 'public-firewall-condition.json')
    $comparison.preflight_allowed = Invoke-PingPreflight 'physical-interface ICMP allow active'
    Write-Json $comparison.preflight_allowed (Join-Path $OutputDir 'preflight-icmp-allow.json')
    $validationScript = Join-Path $PSScriptRoot 'run_validation.ps1'
    & pwsh -NoLogo -NoProfile -File $validationScript -KernelPath $KernelPath -BestTracePath $BestTracePath `
        -Targets $Target -SkipLegacy -MaxHops 32 -BestTraceTimeout 150 -OutputDir $runtimeDirectory 2>&1 |
        Tee-Object -FilePath (Join-Path $OutputDir 'validation-command.log')
    $validationExit = $LASTEXITCODE
    $comparison.validation_exit_code = $validationExit
    if (-not (Test-Path -LiteralPath $comparison.validation_summary_path)) { throw 'Validation did not produce a runtime summary.' }
    $validation = Get-Content -LiteralPath $comparison.validation_summary_path -Raw | ConvertFrom-Json -AsHashtable
    $comparison.status = $validation['status']; $comparison.reason = $validation['reason']
    $comparison.scenarios = @($validation['scenarios'])
    $expectedStatuses = @{ 0 = 'pass'; 1 = 'fail'; 2 = 'inconclusive'; 3 = 'blocked' }
    if (-not $expectedStatuses.ContainsKey($validationExit) -or $comparison.status -ne $expectedStatuses[$validationExit]) {
        throw "Validation exit $validationExit is inconsistent with result $($comparison.status)."
    }
} catch {
    $comparison.status = 'blocked'; $comparison.reason = $_.Exception.Message
    $comparison.fatal_error = $_.Exception.ToString(); $validationExit = 3
} finally {
    if ($ruleAdded) {
        try { Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop; $comparison.firewall.removed = $true }
        catch { $comparison.firewall.cleanup_error = $_.Exception.Message; $comparison.status = 'fail'; $comparison.reason = 'Temporary firewall rule cleanup failed.'; $validationExit = 1 }
    }
    $comparison.ended_at = [DateTime]::UtcNow.ToString('o')
    $comparison.validation_exit_code = $validationExit
    Write-Json $comparison.firewall (Join-Path $OutputDir 'public-firewall-condition.json')
    Write-Json $comparison (Join-Path $OutputDir 'comparison-summary.json')
}
Write-Host "Public comparison $Target`: $($comparison.status) - $($comparison.reason)"
if ($validationExit -eq 2) { Write-Host '::notice::This public comparison is INCONCLUSIVE, not a pass; inspect OFF baseline and captured packets.' }
exit $validationExit

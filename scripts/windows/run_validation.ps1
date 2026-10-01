# Run on an administrator Windows session. Results remain inconclusive when
# the hosted network has no usable baseline or the real BestTrace GUI is blocked.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$KernelPath,
    [Parameter(Mandatory = $true)][string]$BestTracePath,
    [string]$OutputDir = 'windows-validation',
    [string[]]$Targets = @('1.1.1.1', '8.8.8.8'),
    [ValidateRange(15, 120)][int]$BestTraceTimeout = 90,
    [switch]$SkipPacketCapture,
    [switch]$UseFixture,
    [switch]$AllowIcmpErrors
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$script:StartedAt = [DateTime]::UtcNow
$script:Helper = Join-Path $PSScriptRoot 'besttrace_gui.py'
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:PacketFilter = 'MihomoICMPValidation' + $PID
$script:ActiveCapture = $false
$script:FixtureProcess = $null
$script:FixtureDirectory = $null
$script:FixtureStopFile = $null
$script:FirewallRuleName = $null

function Write-Json($Object, [string]$Path) {
    ConvertTo-Json -InputObject $Object -Depth 20 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Quote-WindowsArgument([string]$Value) {
    # CommandLineToArgvW quoting, including trailing backslashes and quotes.
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

function Start-CapturedProcess([string]$Executable, [string[]]$Arguments, [string]$Directory, [string]$Stem) {
    $quoted = @($Arguments | ForEach-Object { Quote-WindowsArgument $_ }) -join ' '
    return Start-Process -FilePath $Executable -ArgumentList $quoted -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Directory ($Stem + '.stdout.log')) `
        -RedirectStandardError (Join-Path $Directory ($Stem + '.stderr.log'))
}

function Wait-CapturedProcess($Process, [int]$Seconds) {
    $finished = $Process.WaitForExit($Seconds * 1000)
    if (-not $finished) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        [void]$Process.WaitForExit(5000)
    }
    $Process.Refresh()
    return [ordered]@{ exit_code = $Process.ExitCode; timed_out = -not $finished; pid = $Process.Id }
}

function Save-NetworkState([string]$Directory, [string]$Stem) {
    $state = [ordered]@{
        at = [DateTime]::UtcNow.ToString('o')
        adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress)
        interfaces = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceIndex, InterfaceMetric, ConnectionState)
        addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceIndex, IPAddress, PrefixLength)
        routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, InterfaceIndex, InterfaceAlias, RouteMetric)
    }
    Write-Json $state (Join-Path $Directory ($Stem + '.json'))
}

function Get-PhysicalExit([string]$Target) {
    $found = @(Find-NetRoute -RemoteIPAddress $Target -ErrorAction Stop)
    $indices = @($found | ForEach-Object { $_.InterfaceIndex } | Select-Object -Unique)
    foreach ($index in $indices) {
        $adapter = Get-NetAdapter -InterfaceIndex $index -ErrorAction SilentlyContinue
        if ($null -ne $adapter -and $adapter.Status -eq 'Up') {
            return [ordered]@{
                name = [string]$adapter.Name
                index = [int]$index
                description = [string]$adapter.InterfaceDescription
                addresses = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 | ForEach-Object { $_.IPAddress })
            }
        }
    }
    throw "No usable outbound adapter found for $Target"
}

function Read-Tracert([string]$Path, [string]$Target) {
    $hops = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -LiteralPath $Path) {
        foreach ($line in Get-Content -LiteralPath $Path) {
            if ($line -match '^\s*(\d+)\s+') {
                $hop = [int]$Matches[1]
                foreach ($match in [regex]::Matches($line, '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')) {
                    $address = $null
                    if ([System.Net.IPAddress]::TryParse($match.Value, [ref]$address)) {
                        $hops.Add([ordered]@{ hop = $hop; address = $match.Value; line = $line })
                    }
                }
            }
        }
    }
    return [ordered]@{
        hops = @($hops.ToArray())
        intermediate_hops = @($hops.ToArray() | Where-Object { $_.address -ne $Target })
        destination_seen = @($hops.ToArray() | Where-Object { $_.address -eq $Target }).Count -gt 0
    }
}

function Invoke-PingApi([string]$Target, [string]$Directory) {
    $records = [System.Collections.Generic.List[object]]::new()
    $ping = [System.Net.NetworkInformation.Ping]::new()
    $payload = [System.Text.Encoding]::ASCII.GetBytes('mihomo-windows-icmp-api-validation')
    try {
        foreach ($ttl in @(1, 2, 3, 8)) {
            try {
                $options = [System.Net.NetworkInformation.PingOptions]::new($ttl, $false)
                $reply = $ping.Send($Target, 1000, $payload, $options)
                $records.Add([ordered]@{
                    ttl = $ttl; status = $reply.Status.ToString(); address = [string]$reply.Address
                    roundtrip_ms = $reply.RoundtripTime
                    data_hex = $(if ($null -eq $reply.Buffer) { '' } else { [Convert]::ToHexString($reply.Buffer) })
                    error = $null
                })
            } catch {
                $records.Add([ordered]@{ ttl = $ttl; status = 'Error'; address = $null; roundtrip_ms = $null; data_hex = $null; error = $_.Exception.ToString() })
            }
        }
    } finally { $ping.Dispose() }
    Write-Json @($records.ToArray()) (Join-Path $Directory 'windows-icmp-api.json')
    return @($records.ToArray())
}

function Read-FixtureEvidence([double]$StartedAt) {
    $evidence = [ordered]@{ status = 'inconclusive'; physical_echo_count = 0; injected_time_exceeded_count = 0; physical_ttls = @(); replied_router_addresses = @(); errors = @() }
    $eventsPath = Join-Path $script:FixtureDirectory 'events.jsonl'
    if (-not (Test-Path $eventsPath)) { $evidence.errors = @('No fixture events'); return $evidence }
    $events = [System.Collections.Generic.List[object]]::new()
    foreach ($line in Get-Content -LiteralPath $eventsPath) {
        try {
            $event = $line | ConvertFrom-Json -AsHashtable
            if ($event.timestamp -ge $StartedAt) { $events.Add($event) }
        } catch { } # The fixture may currently be appending its final line.
    }
    $echo = @($events.ToArray() | Where-Object { $_.event -eq 'physical_egress_echo' })
    $reply = @($events.ToArray() | Where-Object { $_.event -eq 'injected_reply' })
    $evidence.physical_echo_count = $echo.Count
    $evidence.physical_ttls = @($echo | ForEach-Object { [int]$_.probe.ttl } | Sort-Object -Unique)
    $errors = @($events.ToArray() | Where-Object { $_.event -eq 'error' })
    $evidence.errors = @($errors | ForEach-Object { $_.message })
    # Record the complete per-scenario event slice separately for packet-level
    # ID, sequence and checksum review. Raw bytes are never printed in CI logs.
    $evidence.events = @($events.ToArray())
    $evidence.injected_reply_count = $reply.Count
    $routerReplies = @($reply | Where-Object { $_.reply.type -eq 11 })
    $evidence.injected_time_exceeded_count = $routerReplies.Count
    $evidence.replied_router_addresses = @($routerReplies | ForEach-Object {
        if ($_.reply.Contains('source')) { $_.reply.source }
    } | Sort-Object -Unique)
    if ($echo.Count -gt 0 -and $reply.Count -gt 0 -and $errors.Count -eq 0) { $evidence.status = 'recorded' }
    return $evidence
}

function Check-FixtureTools($Tools, [string]$Target) {
    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($expected in @(
        @{ hop = 1; address = '192.0.2.1' },
        @{ hop = 2; address = '192.0.2.2' },
        @{ hop = 3; address = $Target }
    )) {
        $guiSeen = @($Tools.besttrace.hops | Where-Object { $_.hop -eq $expected.hop -and $_.address -eq $expected.address }).Count -gt 0
        $tracertSeen = @($Tools.tracert.hops | Where-Object { $_.hop -eq $expected.hop -and $_.address -eq $expected.address }).Count -gt 0
        $checks.Add([ordered]@{ tool = 'BestTrace'; hop = $expected.hop; address = $expected.address; passed = $guiSeen })
        $checks.Add([ordered]@{ tool = 'tracert'; hop = $expected.hop; address = $expected.address; passed = $tracertSeen })
    }
    foreach ($expected in @(
        @{ ttl = 1; address = '192.0.2.1'; status = 'TtlExpired' },
        @{ ttl = 2; address = '192.0.2.2'; status = 'TtlExpired' },
        @{ ttl = 3; address = $Target; status = 'Success' },
        @{ ttl = 8; address = $Target; status = 'Success' }
    )) {
        $seen = @($Tools.windows_icmp_api | Where-Object {
            $_.ttl -eq $expected.ttl -and $_.status -eq $expected.status -and $_.address -eq $expected.address
        }).Count -gt 0
        $checks.Add([ordered]@{ tool = '.NET Ping'; ttl = $expected.ttl; address = $expected.address; status = $expected.status; passed = $seen })
    }
    return [ordered]@{ passed = @($checks.ToArray() | Where-Object { -not $_.passed }).Count -eq 0; checks = @($checks.ToArray()) }
}

function Start-PacketCapture([string]$Directory) {
    $result = [ordered]@{ status = 'unavailable'; reason = $null; etl = $null; pcapng = $null; analysis = $null }
    if ($SkipPacketCapture) { $result.reason = 'Explicitly disabled'; return $result }
    $pktmon = Get-Command pktmon.exe -ErrorAction SilentlyContinue
    if ($null -eq $pktmon) { $result.reason = 'pktmon.exe unavailable'; return $result }
    try {
        # Filter by protocol, not outer target IP: a router's Time Exceeded has
        # neither the target source nor destination in its outer IP header.
        $filterOutput = & $pktmon.Source filter add $script:PacketFilter -t ICMP 2>&1
        $filterOutput | Set-Content (Join-Path $Directory 'pktmon-filter.log')
        if ($LASTEXITCODE -ne 0) { throw 'Could not add ICMP packet filter' }
        $etl = Join-Path $Directory 'icmp.etl'
        $startOutput = & $pktmon.Source start --capture --comp all --pkt-size 0 --file-name $etl 2>&1
        $startOutput | Set-Content (Join-Path $Directory 'pktmon-start.log')
        if ($LASTEXITCODE -ne 0) { throw 'Could not start pktmon capture' }
        $script:ActiveCapture = $true
        $result.status = 'recording'; $result.etl = $etl
    } catch {
        $result.reason = $_.Exception.Message
        & $pktmon.Source filter remove $script:PacketFilter 2>&1 | Out-File (Join-Path $Directory 'pktmon-filter-cleanup.log')
    }
    return $result
}

function Stop-PacketCapture($Capture, [string]$Directory, [string]$Target, $PhysicalExit) {
    if (-not $script:ActiveCapture) { return }
    try {
        & pktmon.exe stop 2>&1 | Out-File (Join-Path $Directory 'pktmon-stop.log')
        $script:ActiveCapture = $false
        $pcap = Join-Path $Directory 'icmp.pcapng'
        & pktmon.exe etl2pcap $Capture.etl --out $pcap 2>&1 | Out-File (Join-Path $Directory 'pktmon-convert.log')
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $pcap)) { throw 'pktmon ETL conversion failed' }
        $Capture.status = 'recorded'; $Capture.pcapng = $pcap
        # No extra dependencies: parse the pcapng packet records and correlate
        # quoted requests with actual low-TTL Echo packets from the egress IP.
        $parser = @'
import json,struct,sys,ipaddress,hashlib
path,target,physical_json,out=sys.argv[1:]
physical=set(json.loads(physical_json)); data=open(path,'rb').read()
endian='<'; interfaces=[]; packets=[]; seen=set(); offset=0; unsupported=set(); errors=[]; raw_under_ethernet=0
def looks_like_raw_ipv4(frame):
    if len(frame)<20 or frame[0]>>4!=4:return False
    h=(frame[0]&15)*4;total=struct.unpack('!H',frame[2:4])[0]
    return h>=20 and h<=len(frame) and total>=h and total<=len(frame) and frame[9]==1
def ipv4(frame,link):
    global raw_under_ethernet
    if link==1:
        # Windows Pktmon declares Ethernet for Wintun components, while
        # actual captured Wintun bytes are raw IP. Validate that layout first.
        if looks_like_raw_ipv4(frame):raw_under_ethernet+=1
        else:
            if len(frame)<14:return None
            proto=struct.unpack('!H',frame[12:14])[0]; pos=14
            while proto in (0x8100,0x88a8) and len(frame)>=pos+4:
                proto=struct.unpack('!H',frame[pos+2:pos+4])[0];pos+=4
            if proto!=0x0800:return None
            frame=frame[pos:]
    elif link==113:frame=frame[16:]
    elif link==276:frame=frame[20:]
    elif link==0:frame=frame[4:]
    elif link not in (101,228):unsupported.add(link);return None
    if len(frame)<20 or frame[0]>>4!=4 or frame[9]!=1:return None
    h=(frame[0]&15)*4;total=struct.unpack('!H',frame[2:4])[0]
    if h<20 or len(frame)<h+8 or total<h+8:return None
    b=frame[h:min(total,len(frame))]
    r={'src':str(ipaddress.IPv4Address(frame[12:16])),'dst':str(ipaddress.IPv4Address(frame[16:20])),
       'ttl':frame[8],'type':b[0],'code':b[1],'id':struct.unpack('!H',b[4:6])[0],'sequence':struct.unpack('!H',b[6:8])[0]}
    if b[0] in (3,11,12) and len(b)>=8+20+8:
        q=b[8:];qh=(q[0]&15)*4
        if q[0]>>4==4 and qh>=20 and len(q)>=qh+8 and q[9]==1:
            r['quote']={'src':str(ipaddress.IPv4Address(q[12:16])),'dst':str(ipaddress.IPv4Address(q[16:20])),
              'ttl':q[8],'type':q[qh],'id':struct.unpack('!H',q[qh+4:qh+6])[0], 'sequence':struct.unpack('!H',q[qh+6:qh+8])[0]}
    return r
while offset+12<=len(data):
    if data[offset:offset+4]==b'\x0a\x0d\x0d\x0a':
        endian='<' if data[offset+8:offset+12]==b'\x4d\x3c\x2b\x1a' else '>';interfaces=[]
    kind,size=struct.unpack_from(endian+'II',data,offset)
    if size<12 or offset+size>len(data):errors.append('truncated/invalid pcapng block');break
    block=data[offset+8:offset+size-4]
    if kind==1 and len(block)>=8:interfaces.append(struct.unpack_from(endian+'H',block)[0])
    if kind==6 and len(block)>=20:
        idx,hi,lo,cap,original=struct.unpack_from(endian+'IIIII',block)
        if idx<len(interfaces) and 20+cap<=len(block):
            frame=block[20:20+cap];digest=hashlib.sha256(frame).digest()
            if digest not in seen:
                seen.add(digest);p=ipv4(frame,interfaces[idx])
                if p:packets.append(p)
    offset+=size
echo=[p for p in packets if p['type']==8 and p['dst']==target and p['src'] in physical]
keys={(p['id'],p['sequence']) for p in echo if p['ttl']<=12}
errors_from_routers=[p for p in packets if p['type']==11 and p['src']!=target and p['dst'] in physical
                    and p.get('quote',{}).get('dst')==target and (p['quote']['id'],p['quote']['sequence']) in keys]
restored=[p for p in packets if p['type']==11 and p['src']!=target and p.get('quote',{}).get('dst')==target
          and p['dst'] not in physical and p.get('quote',{}).get('src') not in physical]
result={'status':'verified' if errors_from_routers else 'inconclusive',
  'icmp_packet_count':len(packets),'physical_echo_requests':echo,'physical_time_exceeded':errors_from_routers,
  'possible_tun_restored_time_exceeded':restored,'router_addresses':sorted({p['src'] for p in errors_from_routers}),
  'observed_egress_ttls':sorted({p['ttl'] for p in echo}),
  'raw_ipv4_under_ethernet_linktype':raw_under_ethernet,'unsupported_linktypes':sorted(unsupported),'errors':errors}
open(out,'w',encoding='utf-8').write(json.dumps(result,indent=2))
'@
        $analysisPath = Join-Path $Directory 'packet-analysis.json'
        $addressesJson = ConvertTo-Json -InputObject @($PhysicalExit.addresses) -Compress
        $arguments = @('-c', $parser, $pcap, $Target, $addressesJson, $analysisPath)
        $process = Start-CapturedProcess 'python' $arguments $Directory 'packet-analysis'
        $analysisRun = Wait-CapturedProcess $process 15
        if ($analysisRun.exit_code -ne 0 -or -not (Test-Path $analysisPath)) { throw 'Packet analyzer failed; inspect packet-analysis stderr' }
        $Capture.analysis = Get-Content $analysisPath -Raw | ConvertFrom-Json -AsHashtable
    } catch { $Capture.reason = $_.Exception.Message }
    finally {
        & pktmon.exe filter remove $script:PacketFilter 2>&1 | Out-File (Join-Path $Directory 'pktmon-filter-cleanup.log')
        $script:ActiveCapture = $false
    }
}

function Run-Tools([string]$Target, [string]$Directory) {
    $tracert = Start-CapturedProcess 'tracert.exe' @('-4', '-d', '-h', '12', '-w', '500', $Target) $Directory 'tracert'
    $ping = Start-CapturedProcess 'ping.exe' @('-4', '-n', '2', '-w', '1000', $Target) $Directory 'ping'
    $guiDirectory = Join-Path $Directory 'besttrace'
    [void](New-Item -ItemType Directory -Path $guiDirectory -Force)
    $gui = $null
    $guiFailure = $null
    try {
        $gui = Start-CapturedProcess 'python' @($script:Helper, '--exe', $BestTracePath, '--target', $Target,
            '--output-dir', $guiDirectory, '--timeout', [string]$BestTraceTimeout) $Directory 'besttrace-helper'
    } catch { $guiFailure = $_.Exception.Message }
    $api = @(Invoke-PingApi $Target $Directory)
    if ($null -ne $gui) { $guiRun = Wait-CapturedProcess $gui ($BestTraceTimeout + 15) }
    else { $guiRun = [ordered]@{ exit_code = $null; timed_out = $false; error = $guiFailure } }
    $tracertRun = Wait-CapturedProcess $tracert 35
    $pingRun = Wait-CapturedProcess $ping 8
    $resultPath = Join-Path $guiDirectory 'result.json'
    if (Test-Path -LiteralPath $resultPath) {
        try { $guiResult = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json -AsHashtable }
        catch { $guiResult = [ordered]@{ status = 'blocked'; reason = 'Unreadable BestTrace result.json'; intermediate_hops = @(); hops = @() } }
    } else {
        $guiResult = [ordered]@{ status = 'blocked'; reason = 'BestTrace helper produced no result.json'; intermediate_hops = @(); hops = @() }
    }
    return [ordered]@{
        besttrace = $guiResult; besttrace_process = $guiRun
        tracert = Read-Tracert (Join-Path $Directory 'tracert.stdout.log') $Target
        tracert_process = $tracertRun; ping_process = $pingRun; windows_icmp_api = $api
    }
}

function Run-Scenario([string]$Name, [string]$Target, $PhysicalExit, [string]$Stack, [bool]$TraceEnabled) {
    $scenarioStartedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
    $directory = Join-Path $OutputDir ($Name + '-' + $Target.Replace('.', '_'))
    [void](New-Item -ItemType Directory -Path $directory -Force)
    $result = [ordered]@{
        scenario = $Name; target = $Target; stack = $Stack; icmp_trace = $TraceEnabled
        status = 'blocked'; reason = $null; physical_exit = $PhysicalExit; tun_route_verified = $false
        icmp_handler_log_seen = $false; trace_setup_error = $false; runtime_failure = $false; tools = $null; capture = $null
        directory = $directory; fixture_checks = $null; fixture_evidence = $null
        cleanup = [ordered]@{ graceful_tun_disable = $false; residual_target_routes = @(); error = $null }
    }
    $process = $null; $tunIndex = $null; $port = 19280 + $script:Results.Count
    $device = 'ICMPValidation-' + $Name + '-' + $PID
    Save-NetworkState $directory 'network-before'
    try {
        if ($Name -ne 'baseline') {
            $interfaceYaml = "'" + $PhysicalExit.name.Replace("'", "''") + "'"
            $traceYaml = $TraceEnabled.ToString().ToLowerInvariant()
            $config = @"
mixed-port: 0
port: 0
socks-port: 0
allow-lan: false
mode: rule
log-level: debug
ipv6: false
find-process-mode: off
interface-name: $interfaceYaml
external-controller: 127.0.0.1:$port
geodata-mode: false
geo-auto-update: false
dns:
  enable: false
  enhanced-mode: redir-host
  fallback-filter:
    geoip: false
    geosite: []
tun:
  enable: true
  device: '$device'
  stack: $Stack
  auto-route: true
  auto-detect-interface: false
  strict-route: false
  dns-hijack: []
  route-address:
    - '$Target/32'
  icmp-trace: $traceYaml
  disable-icmp-forwarding: false
  icmp-timeout: 30
rules:
  - MATCH,DIRECT
"@
            $configPath = Join-Path $directory 'config.yaml'
            $config | Set-Content -LiteralPath $configPath -Encoding utf8
            $dataDir = Join-Path $directory 'kernel-data'
            [void](New-Item -ItemType Directory -Path $dataDir -Force)
            $process = Start-CapturedProcess $KernelPath @('-d', $dataDir, '-f', $configPath) $directory 'kernel'
            $deadline = [DateTime]::UtcNow.AddSeconds(25)
            do {
                if ($process.HasExited) { throw 'Mihomo exited before the TUN route became active; inspect kernel logs' }
                $adapter = Get-NetAdapter -Name $device -ErrorAction SilentlyContinue
                if ($null -ne $adapter) {
                    $tunIndex = [int]$adapter.ifIndex
                    $ownedRoutes = @(Get-NetRoute -DestinationPrefix ($Target + '/32') -InterfaceIndex $tunIndex -ErrorAction SilentlyContinue)
                    if ($ownedRoutes.Count -gt 0) {
                        $selected = @(Find-NetRoute -RemoteIPAddress $Target -ErrorAction SilentlyContinue)
                        if (@($selected | Where-Object { $_.InterfaceIndex -eq $tunIndex }).Count -gt 0) {
                            $result.tun_route_verified = $true
                            break
                        }
                    }
                }
                Start-Sleep -Milliseconds 300
            } while ([DateTime]::UtcNow -lt $deadline)
            if (-not $result.tun_route_verified) { throw 'The target /32 did not become the selected Wintun route; refusing bypassed tests' }
            try {
                $active = Invoke-RestMethod -Uri "http://127.0.0.1:$port/configs" -TimeoutSec 3
                Write-Json $active (Join-Path $directory 'active-config.json')
            } catch { $_.Exception.Message | Set-Content (Join-Path $directory 'active-config-error.log') }
        }
        Save-NetworkState $directory 'network-active'
        $result.capture = Start-PacketCapture $directory
        $result.tools = Run-Tools $Target $directory
        if ($Name -eq 'baseline') {
            $result.status = $result.tools.besttrace.status
            $result.reason = $result.tools.besttrace.reason
        } else {
            if ($process.HasExited) { throw 'Mihomo exited while trace tools were running' }
            $log = (Get-Content (Join-Path $directory 'kernel.stdout.log') -Raw -ErrorAction SilentlyContinue) +
                (Get-Content (Join-Path $directory 'kernel.stderr.log') -Raw -ErrorAction SilentlyContinue)
            $escapedTarget = [regex]::Escape($Target)
            $prefix = if ($TraceEnabled) { '\[ICMP TRACE\]' } else { '\[ICMP\]' }
            $result.icmp_handler_log_seen = [bool]($log -match ($prefix + '[^\r\n]*' + $escapedTarget + '[^\r\n]*using DIRECT'))
            $result.trace_setup_error = [bool]($log -match '\[ICMP TRACE\] (setup|send) failed')
            if (-not $result.icmp_handler_log_seen) {
                $result.status = 'fail'; $result.runtime_failure = $true
                $result.reason = 'Target route exists, but the expected ICMP forwarding log is absent'
            } elseif ($result.trace_setup_error) {
                $result.status = 'fail'; $result.runtime_failure = $true
                $result.reason = 'ICMP trace setup/send failed; inspect kernel logs'
            } else {
                $result.status = $result.tools.besttrace.status; $result.reason = $result.tools.besttrace.reason
            }
        }
        if ($UseFixture) {
            $result.fixture_checks = Check-FixtureTools $result.tools $Target
            if ($Name -ne 'legacy-mixed' -and $result.status -eq 'pass' -and -not $result.fixture_checks.passed) {
                $result.status = 'fail'; $result.reason = 'The synthetic ICMP path is not exactly R1/R2/target in BestTrace, tracert and Windows ICMP API; inspect fixture checks'
            }
        }
    } catch {
        $result.reason = $_.Exception.Message
        if ($null -ne $process -and $process.HasExited) { $result.status = 'fail'; $result.runtime_failure = $true }
    } finally {
        if ($null -ne $result.capture) { Stop-PacketCapture $result.capture $directory $Target $PhysicalExit }
        if ($UseFixture -and $null -ne $script:FixtureDirectory) {
            $result.fixture_evidence = Read-FixtureEvidence $scenarioStartedAt
            $eventsPath = Join-Path $directory 'fixture-events.json'
            Write-Json $result.fixture_evidence $eventsPath
            # Preserve raw packet/event evidence once, outside summary.json.
            $result.fixture_evidence.Remove('events')
            $result.fixture_evidence.events_path = $eventsPath
        }
        if ($null -ne $process -and -not $process.HasExited) {
            try {
                # PATCH closes the TUN through Mihomo before terminating the
                # process; /restart would incorrectly spawn another kernel.
                Invoke-RestMethod -Uri "http://127.0.0.1:$port/configs" -Method Patch -ContentType 'application/json' `
                    -Body '{"tun":{"enable":false}}' -TimeoutSec 5 | Out-Null
                $result.cleanup.graceful_tun_disable = $true
                Start-Sleep -Milliseconds 400
            } catch { $result.cleanup.error = $_.Exception.Message }
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            [void]$process.WaitForExit(5000)
        }
        if ($null -ne $tunIndex) {
            # Remove only routes owned by this scenario's newly created adapter.
            Get-NetRoute -DestinationPrefix ($Target + '/32') -InterfaceIndex $tunIndex -ErrorAction SilentlyContinue |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
            $result.cleanup.residual_target_routes = @(Get-NetRoute -DestinationPrefix ($Target + '/32') -InterfaceIndex $tunIndex -ErrorAction SilentlyContinue | Select-Object InterfaceIndex, DestinationPrefix)
        }
        Save-NetworkState $directory 'network-after'
        Write-Json $result (Join-Path $directory 'scenario-result.json')
        $script:Results.Add($result)
    }
    Write-Host "$Name $Target : $($result.status) - $($result.reason)"
    return $result
}

$fatalError = $null
$summary = [ordered]@{
    status = 'blocked'; reason = $null; mode = $(if ($UseFixture) { 'synthetic-icmp-fixture' } else { 'public-network' })
    started_at = $script:StartedAt.ToString('o'); ended_at = $null; scenarios = @(); fixture = $null
    allow_icmp_errors = [bool]$AllowIcmpErrors; firewall = $null
    limitations = @('Only IPv4 real-IP probes are exercised here; Fake-IP, IPv6, Verge service mode and Tailscale coexistence need separate validation.')
}
try {
    if ($env:OS -ne 'Windows_NT') { throw 'This script requires Windows' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights are required for Wintun and raw ICMP' }
    $KernelPath = (Resolve-Path -LiteralPath $KernelPath).Path
    $BestTracePath = (Resolve-Path -LiteralPath $BestTracePath).Path
    $OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
    [void](New-Item -ItemType Directory -Path $OutputDir -Force)
    if (-not (Test-Path $script:Helper)) { throw 'besttrace_gui.py is missing' }
    $summary.firewall = [ordered]@{
        profiles_before = @(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
        diagnostic_rule = $null; removed = $false; cleanup_error = $null
    }
    Write-Json $summary.firewall.profiles_before (Join-Path $OutputDir 'firewall-profiles-before.json')
    if ($AllowIcmpErrors) {
        if (-not $UseFixture) { throw '-AllowIcmpErrors is scoped to the controlled fixture addresses and requires -UseFixture' }
        $script:FirewallRuleName = 'MihomoICMPErrors-' + $PID + '-' + [Guid]::NewGuid().ToString('N')
        $rule = New-NetFirewallRule -Name $script:FirewallRuleName -DisplayName $script:FirewallRuleName `
            -Direction Inbound -Protocol ICMPv4 -IcmpType @('3', '11', '12') -Action Allow -Profile Any `
            -RemoteAddress @('192.0.2.1', '192.0.2.2', '203.0.113.77')
        $summary.firewall.diagnostic_rule = [ordered]@{
            name = $script:FirewallRuleName; direction = 'Inbound'; protocol = 'ICMPv4'
            types = @('3', '11', '12'); remote_addresses = @('192.0.2.1', '192.0.2.2', '203.0.113.77')
            profile = 'Any'; action = 'Allow'; program = 'Any'; enabled = [string]$rule.Enabled
        }
        Write-Json $summary.firewall (Join-Path $OutputDir 'firewall-diagnostic.json')
    }
    if ($UseFixture) {
        $Targets = @('203.0.113.77')
        $summary.limitations += 'Replies are generated by a WinDivert fixture after actual physical egress; this does not validate a real public router path.'
    }
    if (@($Targets).Count -eq 0) { throw 'At least one target is required' }
    foreach ($target in $Targets) {
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($target, [ref]$parsed) -or $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw "Not an IPv4 address: $target" }
    }
    Save-NetworkState $OutputDir 'initial-network'
    if ($UseFixture) {
        $script:FixtureDirectory = Join-Path $OutputDir 'fixture'
        [void](New-Item -ItemType Directory -Path $script:FixtureDirectory -Force)
        $script:FixtureStopFile = Join-Path $script:FixtureDirectory 'stop'
        Remove-Item -LiteralPath $script:FixtureStopFile -Force -ErrorAction SilentlyContinue
        $fixtureHelper = Join-Path $PSScriptRoot 'icmp_fixture.py'
        $fixtureExit = Get-PhysicalExit $Targets[0]
        $script:FixtureProcess = Start-CapturedProcess 'python' @($fixtureHelper, '--target', $Targets[0],
            '--interface-index', [string]$fixtureExit.index, '--output-dir', $script:FixtureDirectory,
            '--stop-file', $script:FixtureStopFile, '--duration', '900') $script:FixtureDirectory 'fixture'
        $readyPath = Join-Path $script:FixtureDirectory 'ready.json'
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        while (-not (Test-Path $readyPath) -and [DateTime]::UtcNow -lt $deadline -and -not $script:FixtureProcess.HasExited) {
            Start-Sleep -Milliseconds 200
        }
        if (-not (Test-Path $readyPath)) { throw 'Synthetic ICMP fixture could not load its driver; inspect fixture stderr/summary' }
        $summary.fixture = Get-Content $readyPath -Raw | ConvertFrom-Json -AsHashtable
    }
    $baseline = $null; $selectedExit = $null
    foreach ($target in $Targets) {
        $exit = Get-PhysicalExit $target
        $candidate = Run-Scenario 'baseline' $target $exit '' $false
        if ($null -eq $baseline) { $baseline = $candidate; $selectedExit = $exit }
        if ($candidate.status -eq 'pass') { $baseline = $candidate; $selectedExit = $exit; break }
    }
    $selectedTarget = $baseline.target
    $legacy = Run-Scenario 'legacy-mixed' $selectedTarget $selectedExit 'mixed' $false
    $mixed = Run-Scenario 'trace-mixed' $selectedTarget $selectedExit 'mixed' $true
    $gvisor = Run-Scenario 'trace-gvisor' $selectedTarget $selectedExit 'gvisor' $true
    $summary.selected_target = $selectedTarget
    $summary.baseline_intermediate_available = $baseline.status -eq 'pass'
    $required = @($mixed, $gvisor)
    $hardFailures = @($required | Where-Object { $_.runtime_failure })
    if ($UseFixture -and $baseline.status -ne 'pass') {
        $summary.status = 'blocked'; $summary.reason = 'The controlled fixture baseline did not show R1/R2/target without TUN; inspect baseline GUI/API results and fixture errors'
    } elseif ($hardFailures.Count -gt 0) {
        $summary.status = 'fail'; $summary.reason = 'At least one patched TUN scenario has a runtime/forwarding failure'
    } elseif ($baseline.status -eq 'blocked' -or @($required | Where-Object { $_.status -eq 'blocked' }).Count -gt 0) {
        $summary.status = 'blocked'; $summary.reason = 'The real Windows BestTrace GUI or a required TUN scenario could not be exercised'
    } elseif ($baseline.status -ne 'pass') {
        $summary.status = 'inconclusive'; $summary.reason = 'BestTrace without TUN has no usable intermediate-hop baseline on this Windows network'
    } elseif (@($required | Where-Object { $_.status -ne 'pass' }).Count -gt 0) {
        $summary.status = 'fail'; $summary.reason = 'BestTrace sees intermediate hops without TUN, but a patched TUN scenario does not'
    } else {
        $packetGaps = @($required | Where-Object { $null -eq $_.capture -or $null -eq $_.capture.analysis -or $_.capture.analysis.status -ne 'verified' })
        if ($UseFixture) {
            $fixtureGaps = @($required | Where-Object {
                $null -eq $_.fixture_evidence -or $_.fixture_evidence.status -ne 'recorded' -or
                1 -notin $_.fixture_evidence.physical_ttls -or 2 -notin $_.fixture_evidence.physical_ttls
            })
            if ($fixtureGaps.Count -gt 0) {
                $summary.status = 'inconclusive'; $summary.reason = 'Tools show the controlled path but the fixture lacks physical TTL1/2 request evidence'
            } else {
                $summary.status = 'pass'; $summary.reason = 'Actual Windows BestTrace, tracert and .NET Ping show the controlled R1/R2/target path in both patched TUN stacks, with selected routes, forwarding logs and physical-egress fixture events'
            }
        } elseif ($packetGaps.Count -gt 0) {
            $summary.status = 'inconclusive'; $summary.reason = 'BestTrace shows intermediate hops through both patched TUN stacks, but independent on-wire Time Exceeded evidence is unavailable'
        } else {
            $summary.status = 'pass'; $summary.reason = 'Actual Windows BestTrace shows intermediate hops in both patched TUN stacks; selected Wintun routes, forwarding logs and correlated physical ICMP errors were observed'
        }
    }
} catch {
    $fatalError = $_.Exception.ToString(); $summary.reason = $_.Exception.Message
} finally {
    if ($null -ne $script:FirewallRuleName) {
        try {
            Remove-NetFirewallRule -Name $script:FirewallRuleName -ErrorAction Stop
            $summary.firewall.removed = $true
        } catch { $summary.firewall.cleanup_error = $_.Exception.Message }
    }
    if ($null -ne $script:FixtureProcess) {
        try {
            'stop' | Set-Content -LiteralPath $script:FixtureStopFile -Encoding ascii
            $summary.fixture_process = Wait-CapturedProcess $script:FixtureProcess 10
            $fixtureSummary = Join-Path $script:FixtureDirectory 'summary.json'
            if (Test-Path $fixtureSummary) { $summary.fixture_summary = Get-Content $fixtureSummary -Raw | ConvertFrom-Json -AsHashtable }
        } catch { $summary.fixture_cleanup_error = $_.Exception.Message }
    }
    [void](New-Item -ItemType Directory -Path $OutputDir -Force)
    $summary.ended_at = [DateTime]::UtcNow.ToString('o')
    $summary.elapsed_seconds = [math]::Round(([DateTime]::UtcNow - $script:StartedAt).TotalSeconds, 2)
    $summary.scenarios = @($script:Results.ToArray())
    $summary.fatal_error = $fatalError
    Write-Json $summary (Join-Path $OutputDir 'summary.json')
}
Write-Host "Windows BestTrace validation: $($summary.status) - $($summary.reason)"
if ($summary.status -eq 'pass') { exit 0 }
if ($summary.status -eq 'inconclusive') { exit 2 }
if ($summary.status -eq 'blocked') { exit 3 }
exit 1

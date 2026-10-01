#!/usr/bin/env python3
"""Deterministic Windows IPv4 ICMP path, after Mihomo's physical egress.

Run as Administrator with Python 3 and ``pydivert==2.1.0`` installed. The
PyPI wheel includes signed WinDivert 1.3 binaries; driver loading failures
must be reported as infrastructure failures, not ICMP trace failures.

Only outbound Echo requests for --target on --interface-index are dropped.
Packets on the TUN interface are passed through unchanged. Replies use the
captured *egress* identifier and sequence, so Mihomo must receive them on its
raw socket and restore the original application probe before BestTrace can
display the path. Selecting the actual physical adapter is essential.

This is a synthetic path (192.0.2.1, 192.0.2.2, target), not proof of public
Internet traceroute. Keep its results separate from public path tests.

Example:
  python icmp_fixture.py --interface-index 6 --output-dir fixture \
      --stop-file fixture.stop --duration 900
  python icmp_fixture.py --self-test
"""

from __future__ import annotations

import argparse
import importlib.metadata
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import threading
import time
from typing import BinaryIO


DEFAULT_TARGET = "203.0.113.77"
HOPS = ("192.0.2.1", "192.0.2.2")


def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum, including odd-length payloads."""
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_echo(raw: bytes) -> dict:
    if len(raw) < 28 or raw[0] >> 4 != 4:
        raise ValueError("not a complete IPv4 ICMP packet")
    ihl = (raw[0] & 15) * 4
    total = struct.unpack_from("!H", raw, 2)[0]
    if ihl < 20 or total < ihl + 8 or total > len(raw):
        raise ValueError("invalid IPv4 header/packet length")
    if raw[9] != 1 or raw[ihl:ihl + 2] != b"\x08\x00":
        raise ValueError("not an ICMPv4 Echo request")
    if struct.unpack_from("!H", raw, 6)[0] & 0x3FFF:
        raise ValueError("fragmented Echo request is unsupported")
    identifier, sequence = struct.unpack_from("!HH", raw, ihl + 4)
    return {
        "ihl": ihl,
        "length": total,
        "ttl": raw[8],
        "identifier": identifier,
        "sequence": sequence,
        "source": socket.inet_ntoa(raw[12:16]),
        "destination": socket.inet_ntoa(raw[16:20]),
        "ip_checksum_valid": checksum(raw[:ihl]) == 0,
        "icmp_checksum_valid": checksum(raw[ihl:total]) == 0,
    }


def normalize_echo(raw: bytes, probe: dict) -> bytes:
    """Materialize IP/ICMP checksums when Windows checksum offload is pending."""
    packet = bytearray(raw[:probe["length"]])
    ihl = probe["ihl"]
    packet[ihl + 2:ihl + 4] = b"\0\0"
    struct.pack_into("!H", packet, ihl + 2, checksum(bytes(packet[ihl:])))
    packet[10:12] = b"\0\0"
    struct.pack_into("!H", packet, 10, checksum(bytes(packet[:ihl])))
    return bytes(packet)


def ipv4_packet(source: str, destination: str, body: bytes, identifier: int) -> bytes:
    header = bytearray(struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), identifier & 0xFFFF,
        0, 64, 1, 0, socket.inet_aton(source), socket.inet_aton(destination),
    ))
    struct.pack_into("!H", header, 10, checksum(bytes(header)))
    return bytes(header) + body


def make_reply(raw: bytes, packet_identifier: int = 1) -> tuple[bytes, dict, bytes]:
    probe = parse_echo(raw)
    normalized = normalize_echo(raw, probe)
    if probe["ttl"] <= 2:
        source = HOPS[max(1, probe["ttl"]) - 1]
        # RFC 792 minimum quote: complete original IP header + eight ICMP bytes.
        # Preserve the physical-egress identifier/sequence and original TTL.
        quote = normalized[:probe["ihl"] + 8]
        body = bytearray(b"\x0b\x00\0\0\0\0\0\0" + quote)
    else:
        source = probe["destination"]
        body = bytearray(normalized[probe["ihl"]:])
        body[0] = 0
        body[2:4] = b"\0\0"
    struct.pack_into("!H", body, 2, checksum(bytes(body)))
    reply = ipv4_packet(source, probe["source"], bytes(body), packet_identifier)
    metadata = {
        "type": body[0], "code": body[1], "source": source,
        "destination": probe["source"], "length": len(reply),
        "ip_checksum_valid": checksum(reply[:20]) == 0,
        "icmp_checksum_valid": checksum(reply[20:]) == 0,
        "identifier": probe["identifier"], "sequence": probe["sequence"],
    }
    if body[0] == 11:
        metadata["quoted_ttl"] = normalized[8]
        metadata["quoted_ip_checksum_valid"] = checksum(normalized[:probe["ihl"]]) == 0
    return reply, metadata, normalized


class PcapWriter:
    """Classic little-endian PCAP, LINKTYPE_RAW (101), no fake Ethernet."""

    def __init__(self, path: Path):
        self.file: BinaryIO = path.open("wb")
        self.file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        self.index = 0

    def write(self, raw: bytes, timestamp: float) -> int:
        self.index += 1
        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1_000_000)
        self.file.write(struct.pack("<IIII", seconds, microseconds, len(raw), len(raw)))
        self.file.write(raw)
        self.file.flush()
        return self.index

    def close(self):
        self.file.close()


def self_test():
    """Verify real wire encodings without importing Windows-only pydivert."""
    for ttl in (1, 2, 3, 64):
        for payload in (b"odd", b"even", bytes(range(32))):
            echo = bytearray(struct.pack("!BBHHH", 8, 0, 0, 0xA123, 0xB456) + payload)
            struct.pack_into("!H", echo, 2, checksum(bytes(echo)))
            request = bytearray(ipv4_packet("10.0.0.7", DEFAULT_TARGET, bytes(echo), 90))
            request[8] = ttl
            request[10:12] = b"\0\0"
            struct.pack_into("!H", request, 10, checksum(bytes(request[:20])))
            reply, info, normalized = make_reply(bytes(request))
            assert info["ip_checksum_valid"] and info["icmp_checksum_valid"]
            assert info["identifier"] == 0xA123 and info["sequence"] == 0xB456
            if ttl <= 2:
                assert info["type"] == 11 and info["source"] == HOPS[ttl - 1]
                assert reply[28:] == normalized[:28]
                assert struct.unpack_from("!HH", reply, 52) == (0xA123, 0xB456)
            else:
                assert info["type"] == 0 and reply[28:] == payload
    # Include original IPv4 options in the quote; malformed input must fail closed.
    body = bytearray(struct.pack("!BBHHH", 8, 0, 0, 13, 14) + b"x")
    struct.pack_into("!H", body, 2, checksum(bytes(body)))
    request = bytearray(ipv4_packet("10.0.0.7", DEFAULT_TARGET, bytes(body), 2))
    request[0] = 0x46
    request[8] = 1
    request[20:20] = b"\x01\x01\x01\x00"
    struct.pack_into("!H", request, 2, len(request))
    reply, info, normalized = make_reply(bytes(request))
    assert reply[28:] == normalized[:32] and info["quoted_ip_checksum_valid"]
    for bad in (b"", b"x" * 28, bytes(request[:23])):
        try:
            make_reply(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed input accepted")
    print("ICMP fixture packet self-test passed (13 valid cases + malformed packets)")


def run(args) -> int:
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    # A reused artifact directory must not claim a failed startup is ready.
    (output / "ready.json").unlink(missing_ok=True)
    events = (output / "events.jsonl").open("w", encoding="utf-8", buffering=1)
    pcap = PcapWriter(output / "fixture.pcap")
    stop = threading.Event()
    started = time.time()
    counts = {"captured": 0, "replied": 0, "passthrough": 0, "errors": 0}
    handle = None
    outcome = "starting"

    def log(event: str, **fields):
        entry = {"timestamp": time.time(), "event": event, **fields}
        events.write(json.dumps(entry, sort_keys=True) + "\n")

    def close_handle():
        if handle is not None and handle.is_open:
            try:
                handle.close()
            except OSError:
                pass

    def on_signal(signum, frame):
        stop.set()
        close_handle()

    def watchdog():
        deadline = time.monotonic() + args.duration if args.duration else float("inf")
        while not stop.wait(0.1):
            if (args.stop_file and args.stop_file.exists()) or time.monotonic() >= deadline:
                stop.set()
                close_handle()  # Unblocks WinDivertRecv, including when no probes arrive.
                break

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    try:
        if sys.platform != "win32":
            raise RuntimeError("driver-backed fixture requires Windows; use --self-test on Linux")
        import pydivert
        filter_text = f"outbound and ip and icmp and icmp.Type == 8 and ip.DstAddr == {args.target}"
        handle = pydivert.WinDivert(filter_text)
        handle.open()
        ready = {
            "pid": os.getpid(), "target": args.target,
            "interface_index": args.interface_index, "synthetic_hops": [*HOPS, args.target],
            "filter": filter_text, "pydivert_version": importlib.metadata.version("pydivert"),
            "started_at": started,
        }
        (output / "ready.json").write_text(json.dumps(ready, indent=2) + "\n", encoding="utf-8")
        log("ready", **ready)
        print(json.dumps({"fixture_ready": True, **ready}), flush=True)
        threading.Thread(target=watchdog, daemon=True).start()
        outcome = "stopped"
        while not stop.is_set():
            try:
                packet = handle.recv(65535)
            except (OSError, RuntimeError):
                if stop.is_set():
                    break
                raise
            raw = bytes(packet.raw)
            observed_at = time.time()
            interface = tuple(packet.interface)
            if interface[0] != args.interface_index:
                counts["passthrough"] += 1
                log("passthrough_other_interface", interface=interface, probe=parse_echo(raw),
                    pcap_index=pcap.write(raw, observed_at))
                handle.send(packet, recalculate_checksum=False)
                continue
            counts["captured"] += 1
            probe = parse_echo(raw)
            log("physical_egress_echo", interface=interface, probe=probe, raw_hex=raw.hex(),
                pcap_index=pcap.write(raw, observed_at))
            reply, info, normalized = make_reply(raw, counts["captured"])
            injected = pydivert.Packet(reply, interface, pydivert.Direction.INBOUND)
            # Checksums are already correct, including the inner quoted IP header.
            sent = handle.send(injected, recalculate_checksum=False).value
            if sent != len(reply):
                raise RuntimeError(f"short WinDivertSend: {sent}/{len(reply)}")
            counts["replied"] += 1
            log("injected_reply", interface=interface, reply=info, raw_hex=reply.hex(),
                normalized_egress_hex=normalized.hex(), pcap_index=pcap.write(reply, time.time()))
    except Exception as error:
        counts["errors"] += 1
        outcome = "failed"
        log("error", message=str(error), exception=type(error).__name__)
        print(f"ICMP fixture failed: {type(error).__name__}: {error}", file=sys.stderr, flush=True)
    finally:
        stop.set()
        close_handle()
        summary = {"outcome": outcome, "synthetic": True, "target": args.target,
                   "interface_index": args.interface_index, "counts": counts,
                   "started_at": started, "finished_at": time.time()}
        log("summary", **summary)
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        pcap.close()
        events.close()
    return 1 if outcome == "failed" else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET, type=lambda x: str(ipaddress.IPv4Address(x)))
    parser.add_argument("--interface-index", type=int, help="physical adapter ifIndex, never the TUN adapter")
    parser.add_argument("--output-dir", type=Path, default=Path("fixture"))
    parser.add_argument("--stop-file", type=Path, help="creating this file closes the capture gracefully")
    parser.add_argument("--duration", type=float, default=900, help="maximum seconds; 0 disables the deadline")
    parser.add_argument("--self-test", action="store_true", help="packet-only checks; no driver or Windows needed")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.interface_index is None or args.interface_index < 1:
        parser.error("--interface-index must be the positive physical adapter ifIndex")
    if args.duration < 0:
        parser.error("--duration cannot be negative")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

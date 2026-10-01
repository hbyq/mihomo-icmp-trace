"""Run as Administrator; exercise native Winsock IP_OPTIONS encoding/reset."""
import ctypes
import json
import socket
import sys

if sys.platform != "win32":
    raise SystemExit("Windows required")

wsa = ctypes.WinDLL("ws2_32", use_last_error=True)
wsa.setsockopt.argtypes = (ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
wsa.setsockopt.restype = ctypes.c_int
wsa.getsockopt.argtypes = (ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))
wsa.getsockopt.restype = ctypes.c_int
wsa.WSAGetLastError.restype = ctypes.c_int


def set_options(sock, data, null=False, length=None):
    buf = ctypes.create_string_buffer(data or b"\0")
    pointer = None if null else ctypes.cast(buf, ctypes.c_void_p)
    count = len(data) if length is None else length
    result = wsa.setsockopt(sock.fileno(), socket.IPPROTO_IP, 1, pointer, count)
    return {"return": result, "error": wsa.WSAGetLastError() if result == -1 else 0,
            "pointer_null": null, "length": count}


def get_options(sock):
    data = ctypes.create_string_buffer(40)
    length = ctypes.c_int(40)
    result = wsa.getsockopt(sock.fileno(), socket.IPPROTO_IP, 1, data, ctypes.byref(length))
    return {"return": result, "error": wsa.WSAGetLastError() if result == -1 else 0,
            "length": length.value, "hex": data.raw[:length.value].hex() if result != -1 else None}


rr40 = b"\x07\x27\x04" + bytes(37)
cases = [("rr40", rr40, False, 40), ("rr39", rr40[:39], False, 39),
         ("rr3", b"\x07\x03\x04", False, 3),
         ("reset_null0", b"", True, 0), ("reset_nonnull0", b"", False, 0),
         ("reset_eol1", bytes(1), False, 1), ("reset_zeros4", bytes(4), False, 4),
         ("reset_null4", b"", True, 4)]
results = []
for name, data, null, length in cases:
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))
        item = {"case": name, "initial": get_options(sock)}
        if name.startswith("reset"):
            item["prime_record_route"] = set_options(sock, rr40)
            item["primed_options"] = get_options(sock)
        item["set"] = set_options(sock, data, null, length)
        item["after"] = get_options(sock)
        results.append(item)
print(json.dumps(results, indent=2))

# Require the production set/reset contract while retaining rejected variants
# in the evidence for diagnosing platform differences.
by_name = {item["case"]: item for item in results}
required = (("rr40", 40), ("reset_nonnull0", 0))
for name, expected_length in required:
    item = by_name[name]
    if item["set"]["return"] != 0 or item["after"]["return"] != 0 or item["after"]["length"] != expected_length:
        raise SystemExit(f"Native IP_OPTIONS contract failed: {name}")

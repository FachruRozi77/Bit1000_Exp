#!/usr/bin/env python3
"""
Profile the worker hot loop in isolation.
Runs 10,000 iterations of private_key_to_address and saves stats to file.
"""

import os
import sys
import time
import hashlib
import cProfile
import pstats
from ctypes import (
    cdll, c_void_p, c_char_p, c_int, c_uint, c_size_t,
    create_string_buffer, byref, POINTER
)

try:
    import base58
except ImportError:
    print("[!] pip install base58")
    sys.exit(1)

# ── libsecp256k1.so ──
LIB_PATHS = [
    os.environ.get("LIBSECP256K1_PATH"),
    "/data/data/com.termux/files/usr/lib/libsecp256k1.so",
    "/usr/lib/libsecp256k1.so",
    "/usr/local/lib/libsecp256k1.so",
    "/lib/libsecp256k1.so",
    "/usr/lib/x86_64-linux-gnu/libsecp256k1.so",
    "/usr/lib/aarch64-linux-gnu/libsecp256k1.so",
    "libsecp256k1.so",
]

_lib = None
for path in LIB_PATHS:
    if not path:
        continue
    try:
        _lib = cdll.LoadLibrary(path)
        print(f"[*] Loaded: {path}")
        break
    except OSError:
        continue

if _lib is None:
    print("[!] libsecp256k1.so not found")
    sys.exit(1)

SECP256K1_CONTEXT_SIGN   = 513
SECP256K1_CONTEXT_VERIFY = 257
SECP256K1_EC_COMPRESSED   = 258

_lib.secp256k1_context_create.argtypes = [c_uint]
_lib.secp256k1_context_create.restype = c_void_p
_lib.secp256k1_context_randomize.argtypes = [c_void_p, c_char_p]
_lib.secp256k1_context_randomize.restype = c_int
_lib.secp256k1_ec_pubkey_create.argtypes = [c_void_p, c_void_p, c_char_p]
_lib.secp256k1_ec_pubkey_create.restype = c_int
_lib.secp256k1_ec_pubkey_serialize.argtypes = [
    c_void_p, c_char_p, POINTER(c_size_t), c_void_p, c_uint
]
_lib.secp256k1_ec_pubkey_serialize.restype = c_int

_ctx = _lib.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
_lib.secp256k1_context_randomize(_ctx, os.urandom(32))

_pubkey_buf = create_string_buffer(64)
_serialized = create_string_buffer(33)
_size = c_size_t(33)

# ── Helpers ──
def _ripemd160_sha256(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

def private_key_to_address(pk_int: int):
    seckey = pk_int.to_bytes(32, "big")
    ret = _lib.secp256k1_ec_pubkey_create(_ctx, _pubkey_buf, seckey)
    if ret != 1:
        raise RuntimeError("pubkey_create failed")
    _size.value = 33
    ret = _lib.secp256k1_ec_pubkey_serialize(
        _ctx, _serialized, byref(_size), _pubkey_buf, SECP256K1_EC_COMPRESSED
    )
    if ret != 1:
        raise RuntimeError("serialize failed")
    pub_comp = bytes(_serialized[:33])
    h = _ripemd160_sha256(pub_comp)
    addr = base58.b58encode(b"\x00" + h + hashlib.sha256(hashlib.sha256(b"\x00" + h).digest()).digest()[:4]).decode()
    return addr

# ── Target address for puzzle #71 ──
TARGET = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
LOW = 2 ** 70
HIGH = 2 ** 71

# ── Profile the hot loop ──
def hot_loop(n: int):
    import random
    rng = random.Random(42)
    found = 0
    for _ in range(n):
        pk = rng.randint(LOW, HIGH - 1)
        addr = private_key_to_address(pk)
        if addr == TARGET:
            found += 1
    return found

print(f"[*] Profiling {10_000} iterations...")
profiler = cProfile.Profile()
profiler.enable()

t0 = time.time()
found = hot_loop(10_000)
t1 = time.time()

profiler.disable()

# Save stats
profiler.dump_stats("profile_worker.prof")
with open("profile_worker.txt", "w") as f:
    stats = pstats.Stats(profiler, stream=f)
    stats.sort_stats("tottime")
    stats.print_stats(30)

print(f"[*] Done: {10_000} keys in {t1-t0:.2f}s ({10_000/(t1-t0):.0f} keys/sec)")
print(f"[*] Stats saved to: profile_worker.prof")
print(f"[*] Text saved to: profile_worker.txt")
print(f"[*] Found matches: {found}")

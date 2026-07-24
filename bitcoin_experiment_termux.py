#!/usr/bin/env python3
"""
Bitcoin Puzzle Transaction — HIGH-SPEED Scanner (#71-#160)
===========================================================
Optimized version using libsecp256k1.so via ctypes.

MAJOR OPTIMIZATION: Compare raw RIPEMD160 hashes (20 bytes) instead of
base58-encoded addresses. Base58 encoding is ~17% of runtime and is only
needed when a match is found (which never happens in practice).

Other optimizations:
- Pre-allocated ctypes buffers (no per-key malloc)
- Reused hashlib.new("ripemd160") object per worker
- Reduced lock contention (stats updated once per batch)
- Larger default batch size (1000)

Reality check: even optimized, brute-forcing puzzle #71+ on a phone
is not realistic. This is for tinkering/understanding the challenge.

Usage:
    python3 bitcoin_puzzle_71_160.py [--workers N] [--batch N] [--puzzles 71,72,135]
"""

import os
import sys
import time
import hashlib
import random
import signal
import argparse
import multiprocessing
from datetime import datetime
from multiprocessing import Manager, Value
from ctypes import (
    cdll, c_void_p, c_char_p, c_int, c_uint, c_size_t,
    create_string_buffer, byref, POINTER
)

try:
    import base58
except ImportError:
    print("[!] Missing base58. Install with: pip install base58")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────
#  libsecp256k1.so LOADING via ctypes
# ─────────────────────────────────────────────────────────────────────────

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
        print(f"[*] Loaded libsecp256k1 from: {path}")
        break
    except OSError:
        continue

if _lib is None:
    print("[!] Could not load libsecp256k1.so")
    print("    Set LIBSECP256K1_PATH env var to the full path.")
    sys.exit(1)

# ── CORRECT libsecp256k1 flags from secp256k1.h source ──
SECP256K1_CONTEXT_NONE   = 1
SECP256K1_CONTEXT_VERIFY = 257     # 1 | 256
SECP256K1_CONTEXT_SIGN   = 513     # 1 | 512
SECP256K1_EC_COMPRESSED   = 258    # 2 | 256
SECP256K1_EC_UNCOMPRESSED = 2      # 2

# Set up function signatures
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

# Create context with SIGN | VERIFY
_ctx = _lib.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
if not _ctx:
    print("[!] Failed to create secp256k1 context")
    sys.exit(1)

_rand32 = os.urandom(32)
_lib.secp256k1_context_randomize(_ctx, _rand32)


# ─────────────────────────────────────────────────────────────────────────
#  PUZZLE TARGETS
# ─────────────────────────────────────────────────────────────────────────
PUZZLES = {
    71:  (70, 71,  "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"),
    72:  (71, 72,  "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR"),
    73:  (72, 73,  "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4"),
    74:  (73, 74,  "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv"),
    76:  (75, 76,  "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF"),
    77:  (76, 77,  "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE"),
    78:  (77, 78,  "15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb"),
    79:  (78, 79,  "1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8"),
    81:  (80, 81,  "15qsCm78whspNQFydGJQk5rexzxTQopnHZ"),
    82:  (81, 82,  "13zYrYhhJxp6Ui1VV7pqa5WDhNWM45ARAC"),
    83:  (82, 83,  "14MdEb4eFcT3MVG5sPFG4jGLuHJSnt1Dk2"),
    84:  (83, 84,  "1CMq3SvFcVEcpLMuuH8PUcNiqsK1oicG2D"),
    86:  (85, 86,  "1K3x5L6G57Y494fDqBfrojD28UJv4s5JcK"),
    87:  (86, 87,  "1PxH3K1Shdjb7gSEoTX7UPDZ6SH4qGPrvq"),
    88:  (87, 88,  "16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf"),
    89:  (88, 89,  "19QciEHbGVNY4hrhfKXmcBBCrJSBZ6TaVt"),
    91:  (90, 91,  "1EzVHtmbN4fs4MiNk3ppEnKKhsmXYJ4s74"),
    92:  (91, 92,  "1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5"),
    93:  (92, 93,  "17Q7tuG2JwFFU9rXVj3uZqRtioH3mx2Jad"),
    94:  (93, 94,  "1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL"),
    96:  (95, 96,  "15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b"),
    97:  (96, 97,  "18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8"),
    98:  (97, 98,  "1CaBVPrwUxbQYYswu32w7Mj4HR4maNoJSX"),
    99:  (98, 99,  "1JWnE6p6UN7ZJBN7TtcbNDoRcjFtuDWoNL"),
    101: (100, 101, "1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n"),
    102: (101, 102, "1PXv28YxmYMaB8zxrKeZBW8dt2HK7RkRPX"),
    103: (102, 103, "1AcAmB6jmtU6AiEcXkmiNE9TNVPsj9DULf"),
    104: (103, 104, "1EQJvpsmhazYCcKX5Au6AZmZKRnzarMVZu"),
    106: (105, 106, "18KsfuHuzQaBTNLASyj15hy4LuqPUo1FNB"),
    107: (106, 107, "15EJFC5ZTs9nhsdvSUeBXjLAuYq3SWaxTc"),
    108: (107, 108, "1HB1iKUqeffnVsvQsbpC6dNi1XKbyNuqao"),
    109: (108, 109, "1GvgAXVCbA8FBjXfWiAms4ytFeJcKsoyhL"),
    111: (110, 111, "1824ZJQ7nKJ9QFTRBqn7z7dHV5EGpzUpH3"),
    112: (111, 112, "18A7NA9FTsnJxWgkoFfPAFbQzuQxpRtCos"),
    113: (112, 113, "1NeGn21dUDDeqFQ63xb2SpgUuXuBLA4WT4"),
    114: (113, 114, "174SNxfqpdMGYy5YQcfLbSTK3MRNZEePoy"),
    116: (115, 116, "1MnJ6hdhvK37VLmqcdEwqC3iFxyWH2PHUV"),
    117: (116, 117, "1KNRfGWw7Q9Rmwsc6NT5zsdvEb9M2Wkj5Z"),
    118: (117, 118, "1PJZPzvGX19a7twf5HyD2VvNiPdHLzm9F6"),
    119: (118, 119, "1GuBBhf61rnvRe4K8zu8vdQB3kHzwFqSy7"),
    121: (120, 121, "1GDSuiThEV64c166LUFC9uDcVdGjqkxKyh"),
    122: (121, 122, "1Me3ASYt5JCTAK2XaC32RMeH34PdprrfDx"),
    123: (122, 123, "1CdufMQL892A69KXgv6UNBD17ywWqYpKut"),
    124: (123, 124, "1BkkGsX9ZM6iwL3zbqs7HWBV7SvosR6m8N"),
    126: (125, 126, "1AWCLZAjKbV1P7AHvaPNCKiB7ZWVDMxFiz"),
    127: (126, 127, "1G6EFyBRU86sThN3SSt3GrHu1sA7w7nzi4"),
    128: (127, 128, "1MZ2L1gFrCtkkn6DnTT2e4PFUTHw9gNwaj"),
    129: (128, 129, "1Hz3uv3nNZzBVMXLGadCucgjiCs5W9vaGz"),
    131: (130, 131, "16zRPnT8znwq42q7XeMkZUhb1bKqgRogyy"),
    132: (131, 132, "1KrU4dHE5WrW8rhWDsTRjR21r8t3dsrS3R"),
    133: (132, 133, "17uDfp5r4n441xkgLFmhNoSW1KWp6xVLD"),
    134: (133, 134, "13A3JrvXmvg5w9XGvyyR4JEJqiLz8ZySY3"),
    135: (134, 135, "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"),
    136: (135, 136, "1UDHPdovvR985NrWSkdWQDEQ1xuRiTALq"),
    137: (136, 137, "15nf31J46iLuK1ZkTnqHo7WgN5cARFK3RA"),
    138: (137, 138, "1Ab4vzG6wEQBDNQM1B2bvUz4fqXXdFk2WT"),
    139: (138, 139, "1Fz63c775VV9fNyj25d9Xfw3YHE6sKCxbt"),
    140: (139, 140, "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"),
    141: (140, 141, "1CD91Vm97mLQvXhrnoMChhJx4TP9MaQkJo"),
    142: (141, 142, "15MnK2jXPqTMURX4xC3h4mAZxyCcaWWEDD"),
    143: (142, 143, "13N66gCzWWHEZBxhVxG18P8wyjEWF9Yoi1"),
    144: (143, 144, "1NevxKDYuDcCh1ZMMi6ftmWwGrZKC6j7Ux"),
    145: (144, 145, "19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg"),
    146: (145, 146, "1M7ipcdYHey2Y5RZM34MBbpugghmjaV89P"),
    147: (146, 147, "18aNhurEAJsw6BAgtANpexk5ob1aGTwSeL"),
    148: (147, 148, "1FwZXt6EpRT7Fkndzv6K4b4DFoT4trbMrV"),
    149: (148, 149, "1CXvTzR6qv8wJ7eprzUKeWxyGcHwDYP1i2"),
    150: (149, 150, "1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy"),
    151: (150, 151, "13Q84TNNvgcL3HJiqQPvyBb9m4hxjS3jkV"),
    152: (151, 152, "1LuUHyrQr8PKSvbcY1v1PiuGuqFjWpDumN"),
    153: (152, 153, "18192XpzzdDi2K11QVHR7td2HcPS6Qs5vg"),
    154: (153, 154, "1NgVmsCCJaKLzGyKLFJfVequnFW9ZvnMLN"),
    155: (154, 155, "1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ"),
    156: (155, 156, "1FTpAbQa4h8trvhQXjXnmNhqdiGBd1oraE"),
    157: (156, 157, "14JHoRAdmJg3XR4RjMDh6Wed6ft6hzbQe9"),
    158: (157, 158, "19z6waranEf8CcP8FqNgdwUe1QRxvUNKBG"),
    159: (158, 159, "14u4nA5sugaswb6SZgn5av2vuChdMnD9E5"),
    160: (159, 160, "1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv"),
}

RESULT_FILE = "found_result.txt"

# ─────────────────────────────────────────────────────────────────────────
#  PRE-COMPUTE TARGET HASHES for fast comparison
#  Bitcoin address = base58(0x00 + hash160 + checksum)
#  hash160 = ripemd160(sha256(pubkey))
#  We decode each target address to extract the inner 20-byte hash160
# ─────────────────────────────────────────────────────────────────────────

def _decode_address_to_hash160(addr: str) -> bytes:
    """Extract the 20-byte hash160 from a base58 Bitcoin address."""
    decoded = base58.b58decode(addr)
    # decoded = [version(1) + hash160(20) + checksum(4)]
    return decoded[1:21]

# Pre-compute: puzzle_num -> (low, high, target_hash160_bytes)
PUZZLE_DATA = {}
for num, (lo, hi, addr) in PUZZLES.items():
    PUZZLE_DATA[num] = (2 ** lo, 2 ** hi, _decode_address_to_hash160(addr))


# ─────────────────────────────────────────────────────────────────────────
#  OPTIMIZED CRYPTO HELPERS
# ─────────────────────────────────────────────────────────────────────────

# Pre-allocate reusable buffers
_pubkey_buf = create_string_buffer(64)
_serialized = create_string_buffer(33)
_size = c_size_t(33)

# Reusable sha256 object
_sha256 = hashlib.sha256

def _hash160(data: bytes) -> bytes:
    """Return 20-byte hash160 = ripemd160(sha256(data))."""
    return hashlib.new("ripemd160", _sha256(data).digest()).digest()


def private_key_to_hash160(pk_int: int) -> bytes:
    """
    Return the 20-byte hash160 (not the base58 address).
    This skips base58 encoding entirely — the major bottleneck.
    """
    seckey = pk_int.to_bytes(32, "big")

    ret = _lib.secp256k1_ec_pubkey_create(_ctx, _pubkey_buf, seckey)
    if ret != 1:
        raise RuntimeError("secp256k1_ec_pubkey_create failed")

    _size.value = 33
    ret = _lib.secp256k1_ec_pubkey_serialize(
        _ctx, _serialized, byref(_size), _pubkey_buf, SECP256K1_EC_COMPRESSED
    )
    if ret != 1:
        raise RuntimeError("secp256k1_ec_pubkey_serialize failed")

    pub_comp = bytes(_serialized[:33])
    return _hash160(pub_comp)


def write_result(addr: str, pk: int, wif: str, puzzle_num: int):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(RESULT_FILE, "a") as fh:
        fh.write("=" * 62 + "\n")
        fh.write(f"  FOUND @ {ts}\n")
        fh.write(f"  Puzzle #   : {puzzle_num}\n")
        fh.write(f"  Address    : {addr}\n")
        fh.write(f"  Private Key: {hex(pk)}\n")
        fh.write(f"  Decimal PK : {pk}\n")
        fh.write(f"  WIF Key    : {wif}\n")
        fh.write("=" * 62 + "\n\n")


def build_wif(pk_int: int) -> str:
    """Build WIF only when a match is found."""
    seckey = pk_int.to_bytes(32, "big")
    payload = b"\x80" + seckey + b"\x01"
    return base58.b58encode(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]).decode()


def build_address(hash160: bytes) -> str:
    """Build base58 address only when a match is found."""
    payload = b"\x00" + hash160
    return base58.b58encode(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]).decode()


# ─────────────────────────────────────────────────────────────────────────
#  WORKER — optimized with raw hash160 comparison
# ─────────────────────────────────────────────────────────────────────────
def worker(worker_id: int, puzzle_nums: list, stats_dict, lock,
           result_lock, stop_flag: Value, batch_size: int):
    rng = random.Random(os.getpid() ^ int(time.time() * 1000))

    # Local puzzle data for fast access
    local_puzzles = {p: PUZZLE_DATA[p] for p in puzzle_nums}

    while not stop_flag.value:
        puzzle_num = rng.choice(puzzle_nums)
        low, high, target_hash160 = local_puzzles[puzzle_num]

        found_batch = 0
        local_checked = 0

        for _ in range(batch_size):
            if stop_flag.value:
                break
            pk = rng.randint(low, high - 1)
            try:
                hash160 = private_key_to_hash160(pk)
            except Exception:
                continue

            local_checked += 1

            # Compare raw 20-byte hashes — NO base58 overhead!
            if hash160 == target_hash160:
                # Only now compute base58 address and WIF
                addr = build_address(hash160)
                wif = build_wif(pk)
                with result_lock:
                    write_result(addr, pk, wif, puzzle_num)
                found_batch += 1

        # Update stats once per batch
        with lock:
            stats_dict["total_checked"] = stats_dict.get("total_checked", 0) + local_checked
            stats_dict["cycles"] = stats_dict.get("cycles", 0) + 1
            wranges = dict(stats_dict.get("worker_ranges", {}))
            wranges[worker_id] = puzzle_num
            stats_dict["worker_ranges"] = wranges
            if found_batch:
                stats_dict["found"] = stats_dict.get("found", 0) + found_batch


# ─────────────────────────────────────────────────────────────────────────
#  DISPLAY
# ─────────────────────────────────────────────────────────────────────────
def draw_status(snap: dict):
    os.system("clear" if sys.platform != "win32" else "cls")
    elapsed = time.time() - snap["start_time"]
    checked = snap.get("total_checked", 0)
    speed = checked / elapsed if elapsed > 0 else 0
    found = snap.get("found", 0)
    wranges = snap.get("worker_ranges", {})

    print("=" * 60)
    print("  BITCOIN PUZZLE #71-#160 — HIGH-SPEED libsecp256k1 SCANNER")
    print("=" * 60)
    print(f"  Workers        : {snap.get('workers', 1)}")
    print(f"  Target puzzles : {snap.get('num_puzzles', 0)} unsolved addresses")
    print(f"  Elapsed        : {int(elapsed)}s")
    print(f"  Keys checked   : {checked:,}")
    print(f"  Speed          : {speed:,.0f} keys/sec")
    print(f"  Cycles         : {snap.get('cycles', 0):,}")
    print("-" * 60)
    for wid in sorted(wranges):
        print(f"    Worker {wid:2d} -> puzzle #{wranges[wid]}")
    print("-" * 60)
    if found > 0:
        print(f"  *** MATCH FOUND: {found} -> see {RESULT_FILE} ***")
    else:
        print("  Searching... no matches yet.")
    print("=" * 60)
    print("  Ctrl+C to stop.")


# ─────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Bitcoin Puzzle Scanner (#71-#160)")
    parser.add_argument("--workers", type=int,
                         default=max(1, multiprocessing.cpu_count() - 1),
                         help="Number of worker processes")
    parser.add_argument("--batch", type=int, default=1000,
                         help="Keys checked per worker cycle (default: 1000)")
    parser.add_argument("--puzzles", type=str, default=None,
                         help="Comma-separated puzzle numbers, e.g. 71,72,135")
    args = parser.parse_args()

    if args.puzzles:
        requested = [int(x.strip()) for x in args.puzzles.split(",")]
        puzzle_nums = [p for p in requested if p in PUZZLES]
        missing = [p for p in requested if p not in PUZZLES]
        if missing:
            print(f"[!] Ignoring puzzles not in unsolved set: {missing}")
    else:
        puzzle_nums = list(PUZZLES.keys())

    if not puzzle_nums:
        print("[!] No valid puzzle numbers to search.")
        sys.exit(1)

    print(f"[*] Targeting {len(puzzle_nums)} unsolved puzzle address(es).")
    print(f"[*] Workers: {args.workers}, batch size: {args.batch}")
    print("[*] OPTIMIZED: raw hash160 comparison (no base58 in hot loop)")
    print("[*] Ctrl+C anytime to stop.\n")
    time.sleep(1.5)

    manager = Manager()
    stats_dict = manager.dict()
    lock = manager.Lock()
    result_lock = manager.Lock()
    stop_flag = Value("b", 0)

    stats_dict["total_checked"] = 0
    stats_dict["cycles"] = 0
    stats_dict["found"] = 0
    stats_dict["start_time"] = time.time()
    stats_dict["workers"] = args.workers
    stats_dict["num_puzzles"] = len(puzzle_nums)
    stats_dict["worker_ranges"] = {}

    processes = []
    for wid in range(args.workers):
        p = multiprocessing.Process(
            target=worker,
            args=(wid, puzzle_nums, stats_dict, lock, result_lock,
                  stop_flag, args.batch),
            daemon=True,
            name=f"worker-{wid}",
        )
        p.start()
        processes.append(p)

    def graceful_shutdown(sig=None, frame=None):
        stop_flag.value = 1
        print("\n\n[!] Stopping workers...")
        for p in processes:
            p.join(timeout=5)
        print("[+] Stopped.\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    time.sleep(1)
    while True:
        try:
            snap = dict(stats_dict)
            draw_status(snap)
            time.sleep(10)
            if not any(p.is_alive() for p in processes):
                print("[!] All workers stopped. Exiting.")
                break
        except KeyboardInterrupt:
            graceful_shutdown()


if __name__ == "__main__":
    if sys.platform != "win32":
        try:
            multiprocessing.set_start_method("fork", force=True)
        except RuntimeError:
            pass
    main()

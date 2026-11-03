"""Independent hash oracle for tests: computes payload_hash / body_hash with
the reference algorithms (lens.py), so test fixtures are never sealed by the
Rust code they are testing.

  python3 pyhash.py payload < payload.json   -> spec §5 payload hash
  python3 pyhash.py body    < body.txt       -> body_hash (lens.normalize_body)
"""
import hashlib, json, os, sys, unicodedata

sys.path.insert(0, os.environ["KNOBE_PROTOCOL_DIR"])
import lens  # noqa: E402

def nfc(x):
    if isinstance(x, str):
        return unicodedata.normalize("NFC", x)
    if isinstance(x, dict):
        return {unicodedata.normalize("NFC", k): nfc(v) for k, v in x.items()}
    if isinstance(x, list):
        return [nfc(v) for v in x]
    return x

data = sys.stdin.buffer.read().decode("utf-8")
if sys.argv[1] == "payload":
    # Hostile fixtures may be unparseable or uncanonicalizable on purpose; the
    # file under test is then unreadable/failed regardless of the hash we emit.
    try:
        p = json.loads(data.lstrip("﻿"), strict=False)
        p.pop("payload_hash", None)
        canon = json.dumps(nfc(p), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        print(hashlib.sha256(canon.encode("utf-8", "surrogatepass")).hexdigest())
    except Exception as e:  # noqa: BLE001
        print(f"oracle: no canonical hash ({e})", file=sys.stderr)
        print("0" * 64)
else:
    print(hashlib.sha256(lens.normalize_body(data).encode("utf-8")).hexdigest())

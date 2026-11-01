"""Manifest signing for the Cobble feed.

The private seed stays on the build machine (keys/cobble_feed.key) and never
ships. The loader embeds only the public key, so a modified payload or a
forged manifest cannot produce a valid signature.

Canonical message: cobble|product|build|size|sha256
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ed25519  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_DIR = os.path.join(ROOT, "keys")
PRIVATE = os.path.join(KEY_DIR, "cobble_feed.key")
PUBLIC = os.path.join(KEY_DIR, "cobble_feed.pub")

# public half of the signing key. this string is compiled into the loader and
# is the only thing a distributed copy needs to check a manifest.
FEED_PUBKEY = "eddba843cf032afe4b50584468bfb2b8ed7eb1d0e23ed23d13dfb7a6b2319a62"


def canonical(man: dict) -> bytes:
    return (
        f"cobble|{man.get('product', 'Cobble')}|{int(man['build'])}|"
        f"{int(man['size'])}|{str(man['sha256']).lower()}|"
        f"{str(man.get('loader_sha256', '')).lower()}"
    ).encode("ascii")


def canonical_feed(man: dict) -> bytes:
    """The feed manifest also attests the loader and the kill list."""
    kill = man.get("kill") or {}
    builds = ",".join(str(int(b)) for b in sorted(kill.get("builds", [])))
    hwids = ",".join(sorted(str(h).lower() for h in kill.get("hwids", [])))
    return (
        f"cobble-feed|{man.get('product', 'Cobble')}|{int(man['build'])}|"
        f"{int(man['size'])}|{str(man['sha256']).lower()}|"
        f"{str(man.get('loader_sha256', '')).lower()}|{builds}|{hwids}"
    ).encode("ascii")


def canonical_loader(build: int, loader_sha: str) -> bytes:
    return f"cobble-loader|{int(build)}|{str(loader_sha).lower()}".encode("ascii")


def canonical_install(build: int, exe_sha: str) -> bytes:
    """Attestation that this exact exe was the one packaged for this build.

    The feed never rewrites it, so a legit payload update cannot be mistaken
    for a patched loader.
    """
    return f"cobble-install|{int(build)}|{str(exe_sha).lower()}".encode("ascii")


def keygen(force: bool = False) -> str:
    os.makedirs(KEY_DIR, exist_ok=True)
    if os.path.exists(PRIVATE) and not force:
        with open(PUBLIC, "r", encoding="ascii") as fh:
            return fh.read().strip()
    seed = os.urandom(32)
    pub = ed25519.public_key(seed)
    with open(PRIVATE, "w", encoding="ascii") as fh:
        fh.write(seed.hex() + "\n")
    with open(PUBLIC, "w", encoding="ascii") as fh:
        fh.write(pub.hex() + "\n")
    try:
        os.chmod(PRIVATE, 0o600)
    except OSError:
        pass
    return pub.hex()


def read_public() -> str:
    with open(PUBLIC, "r", encoding="ascii") as fh:
        return fh.read().strip()


def sign_manifest(man: dict) -> dict:
    with open(PRIVATE, "r", encoding="ascii") as fh:
        seed = bytes.fromhex(fh.read().strip())
    man["sig"] = ed25519.sign(seed, canonical(man)).hex()
    return man


def verify_manifest(man: dict, pubkey_hex: str) -> bool:
    sig = man.get("sig")
    if not sig:
        return False
    try:
        return ed25519.verify(bytes.fromhex(pubkey_hex), canonical(man), bytes.fromhex(sig))
    except (ValueError, TypeError):
        return False


def _seed() -> bytes:
    with open(PRIVATE, "r", encoding="ascii") as fh:
        return bytes.fromhex(fh.read().strip())


def sign_feed(man: dict) -> dict:
    man["feed_sig"] = ed25519.sign(_seed(), canonical_feed(man)).hex()
    return man


def verify_feed(man: dict, pubkey_hex: str) -> bool:
    sig = man.get("feed_sig")
    if not sig:
        return False
    try:
        return ed25519.verify(bytes.fromhex(pubkey_hex), canonical_feed(man), bytes.fromhex(sig))
    except (ValueError, TypeError):
        return False


def sign_loader(man: dict, loader_sha: str) -> dict:
    man["loader_sha256"] = str(loader_sha).lower()
    man["loader_sig"] = ed25519.sign(
        _seed(), canonical_loader(int(man["build"]), loader_sha)
    ).hex()
    return man


def verify_loader(man: dict, pubkey_hex: str, loader_sha: str | None = None) -> bool:
    sig = man.get("loader_sig")
    want = str(man.get("loader_sha256", "")).lower()
    if not sig or not want:
        return False
    if loader_sha is not None and str(loader_sha).lower() != want:
        return False
    try:
        return ed25519.verify(
            bytes.fromhex(pubkey_hex),
            canonical_loader(int(man["build"]), want),
            bytes.fromhex(sig),
        )
    except (ValueError, TypeError):
        return False


def sign_install(build: int, exe_sha: str) -> dict:
    return {
        "product": "Cobble",
        "build": int(build),
        "exe_sha256": str(exe_sha).lower(),
        "sig": ed25519.sign(_seed(), canonical_install(build, exe_sha)).hex(),
    }


def verify_install(rec: dict, pubkey_hex: str) -> bool:
    sig = rec.get("sig")
    want = str(rec.get("exe_sha256", "")).lower()
    if not sig or not want:
        return False
    try:
        return ed25519.verify(
            bytes.fromhex(pubkey_hex),
            canonical_install(int(rec["build"]), want),
            bytes.fromhex(sig),
        )
    except (ValueError, TypeError, KeyError):
        return False


def sha256_file(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description="sign or verify a Cobble manifest")
    ap.add_argument("--keygen", action="store_true", help="create the key pair")
    ap.add_argument("--force", action="store_true", help="overwrite an existing key")
    ap.add_argument("--manifest", default=None, help="manifest.json to sign")
    ap.add_argument("--payload", default=None, help="payload dll the manifest describes")
    ap.add_argument("--loader", default=None, help="loader exe to attest in the manifest")
    ap.add_argument("--install", default=None, help="exe to write an install record for")
    ap.add_argument("--out", default=None, help="install record path")
    ap.add_argument("--check", action="store_true", help="verify instead of sign")
    args = ap.parse_args()

    if args.keygen:
        print(keygen(force=args.force))
        return

    if args.install:
        build = 0
        if args.manifest and os.path.isfile(args.manifest):
            with open(args.manifest, "r", encoding="utf-8") as fh:
                build = int(json.load(fh)["build"])
        record = sign_install(build, sha256_file(args.install))
        out = args.out or os.path.join(os.path.dirname(args.install), "install.json")
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
        print(f"install      {out} (build {build})")
        return

    if not args.manifest:
        raise SystemExit("--manifest is required")

    with open(args.manifest, "r", encoding="utf-8") as fh:
        man = json.load(fh)

    if args.payload:
        man["size"] = os.path.getsize(args.payload)
        man["sha256"] = sha256_file(args.payload)

    if args.check:
        ok = verify_manifest(man, read_public())
        print(f"signature    {'ok' if ok else 'INVALID'}")
        raise SystemExit(0 if ok else 1)

    man["product"] = man.get("product", "Cobble")
    if args.loader:
        sign_loader(man, sha256_file(args.loader))
    sign_manifest(man)
    with open(args.manifest, "w", encoding="utf-8") as fh:
        json.dump(man, fh, indent=2)
    print(f"signed       {args.manifest} (build {man['build']})")


if __name__ == "__main__":
    main()

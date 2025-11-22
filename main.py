#!/usr/bin/env python3
"""
Simple CLI Password Manager (encrypted vault file)
Dependencies: cryptography
Install: pip install cryptography
Usage examples:
  python pwman.py init vault.dat
  python pwman.py add vault.dat example.com --user alice
  python pwman.py get vault.dat example.com
  python pwman.py list vault.dat
  python pwman.py delete vault.dat example.com
  python pwman.py gen 16
"""
import argparse
import base64
import json
import os
import secrets
import sys
from getpass import getpass
from typing import Dict

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ----- crypto helpers -----
def _derive_key(password: str, salt: bytes, iterations: int = 390000) -> bytes:
    pw = password.encode("utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(pw))

def _encrypt_vault(key: bytes, data: Dict) -> bytes:
    f = Fernet(key)
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f.encrypt(raw)

def _decrypt_vault(key: bytes, token: bytes) -> Dict:
    f = Fernet(key)
    raw = f.decrypt(token)
    return json.loads(raw.decode("utf-8"))

# ----- file format helpers -----
def _write_vault_file(path: str, salt: bytes, ciphertext: bytes) -> None:
    payload = {"salt": base64.b64encode(salt).decode("ascii"), "vault": base64.b64encode(ciphertext).decode("ascii")}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def _read_vault_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    salt = base64.b64decode(payload["salt"])
    vault = base64.b64decode(payload["vault"])
    return salt, vault

# ----- vault operations -----
def init_vault(path: str):
    if os.path.exists(path):
        print("Vault already exists.", file=sys.stderr)
        sys.exit(1)
    master = getpass("Set master password: ")
    confirm = getpass("Confirm master password: ")
    if master != confirm:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)
    salt = secrets.token_bytes(16)
    key = _derive_key(master, salt)
    empty = {}
    ciphertext = _encrypt_vault(key, empty)
    _write_vault_file(path, salt, ciphertext)
    print(f"Initialized new vault: {path}")

def load_vault(path: str, prompt: bool = True):
    if not os.path.exists(path):
        print("Vault not found. Initialize with 'init'.", file=sys.stderr)
        sys.exit(1)
    salt, ciphertext = _read_vault_file(path)
    master = getpass("Master password: ") if prompt else ""
    key = _derive_key(master, salt)
    try:
        vault = _decrypt_vault(key, ciphertext)
    except InvalidToken:
        print("Invalid master password or corrupted vault.", file=sys.stderr)
        sys.exit(1)
    return vault, key, salt

def save_vault(path: str, vault: Dict, key: bytes, salt: bytes):
    ciphertext = _encrypt_vault(key, vault)
    _write_vault_file(path, salt, ciphertext)

# ----- CLI command implementations -----
def cmd_add(args):
    vault, key, salt = load_vault(args.vault)
    entry = {
        "username": args.user or "",
        "password": args.password or (secrets.token_urlsafe(16) if args.generate else ""),
        "notes": args.notes or ""
    }
    vault[args.name] = entry
    save_vault(args.vault, vault, key, salt)
    print(f"Added/Updated entry '{args.name}'")

def cmd_get(args):
    vault, _, _ = load_vault(args.vault)
    entry = vault.get(args.name)
    if not entry:
        print("Entry not found.", file=sys.stderr)
        sys.exit(1)
    out = {"service": args.name, **entry}
    print(json.dumps(out, indent=2, ensure_ascii=False))

def cmd_list(args):
    vault, _, _ = load_vault(args.vault)
    for name in sorted(vault.keys()):
        u = vault[name].get("username", "")
        print(f"{name}\t{u}")

def cmd_delete(args):
    vault, key, salt = load_vault(args.vault)
    if args.name in vault:
        del vault[args.name]
        save_vault(args.vault, vault, key, salt)
        print(f"Deleted '{args.name}'")
    else:
        print("Entry not found.", file=sys.stderr)
        sys.exit(1)

def cmd_gen(args):
    # generate a secure password of requested length
    try:
        n = int(args.length)
        if n < 4:
            raise ValueError
    except ValueError:
        print("Length must be an integer >= 4", file=sys.stderr)
        sys.exit(1)
    # secrets.token_urlsafe gives approx 4/3 * n bytes; trim to length
    pwd = secrets.token_urlsafe(n)[:n]
    print(pwd)

def cmd_change_master(args):
    vault, key, salt = load_vault(args.vault)
    new_master = getpass("New master password: ")
    confirm = getpass("Confirm new master password: ")
    if new_master != confirm:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)
    new_salt = secrets.token_bytes(16)
    new_key = _derive_key(new_master, new_salt)
    save_vault(args.vault, vault, new_key, new_salt)
    print("Master password changed.")

# ----- argument parsing -----
def build_parser():
    p = argparse.ArgumentParser(prog="pwman", description="Simple encrypted CLI password manager")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="Initialize a new vault")
    sp.add_argument("vault", help="Vault file path")
    sp.set_defaults(func=lambda a: init_vault(a.vault))

    sp = sub.add_parser("add", help="Add or update an entry")
    sp.add_argument("vault", help="Vault file path")
    sp.add_argument("name", help="Service/entry name (e.g. example.com)")
    sp.add_argument("--user", "-u", help="Username")
    sp.add_argument("--password", "-p", help="Password (omit to auto-generate)")
    sp.add_argument("--generate", "-g", action="store_true", help="Generate a secure password for this entry")
    sp.add_argument("--notes", help="Notes")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("get", help="Get an entry")
    sp.add_argument("vault", help="Vault file path")
    sp.add_argument("name", help="Service/entry name")
    sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("list", help="List entries")
    sp.add_argument("vault", help="Vault file path")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("delete", help="Delete an entry")
    sp.add_argument("vault", help="Vault file path")
    sp.add_argument("name", help="Service/entry name")
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("gen", help="Generate a secure password")
    sp.add_argument("length", help="Password length")
    sp.set_defaults(func=cmd_gen)

    sp = sub.add_parser("changemaster", help="Change master password")
    sp.add_argument("vault", help="Vault file path")
    sp.set_defaults(func=cmd_change_master)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
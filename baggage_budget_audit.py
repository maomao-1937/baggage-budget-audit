"""Check a saved W3C Baggage header value and report propagation budgets."""

import json
import os
import posixpath
import re
import stat
import sys


MAX_INPUT_BYTES = 256 * 1024
MAX_MEMBERS = 180
BYTE_BUDGET = 8192
MEMBER_BUDGET = 64
OWS = b" \t"
TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
INVALID_VALUE = re.compile(rb"[^\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]|%(?![0-9A-Fa-f]{2})")
DEVICE = re.compile(r"CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9¹²³]")
NATIVE_ROOTS = {"??", "device", "dosdevices", "global??", "systemroot", "globalroot"}


def check_path(path):
    spelling = path.replace("\\", "/")
    if not spelling or spelling == "-" or spelling.startswith("//") or spelling.endswith("/"):
        raise ValueError
    if any(ord(char) < 32 for char in spelling):
        raise ValueError
    if spelling.startswith("/"):
        for version in (spelling, posixpath.normpath(spelling)):
            root = version[1:].partition("/")[0].rstrip(" .").lower()
            if root in NATIVE_ROOTS:
                raise ValueError
    tail = spelling[2:] if re.match(r"^[A-Za-z]:/", spelling) else spelling
    if ":" in tail:
        raise ValueError
    for part in tail.split("/"):
        if part in {"", ".", ".."}:
            continue
        stem = part.partition(".")[0].rstrip(" ").upper()
        if part.endswith((" ", ".")) or DEVICE.fullmatch(stem):
            raise ValueError


def check_file(info):
    if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= MAX_INPUT_BYTES:
        raise ValueError


def read_header(path):
    check_file(os.stat(path))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        check_file(os.fstat(descriptor))
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            header = stream.read(MAX_INPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(header) > MAX_INPUT_BYTES:
        raise ValueError
    return header


def field_key(field, require_value):
    key, separator, value = field.partition(b"=")
    key = key.strip(OWS)
    if not TOKEN.fullmatch(key) or (require_value and not separator):
        raise ValueError
    if INVALID_VALUE.search(value.strip(OWS)):
        raise ValueError
    return key


def audit(header):
    members = header.split(b",", MAX_MEMBERS)
    if len(members) > MAX_MEMBERS:
        raise ValueError
    seen = set()
    duplicates = []
    for ordinal, member in enumerate(members, 1):
        fields = member.split(b";")
        key = field_key(fields[0], require_value=True)
        for prop in fields[1:]:
            field_key(prop, require_value=False)
        if key in seen:
            duplicates.append(ordinal)
        seen.add(key)

    byte_budget_exceeded = len(header) > BYTE_BUDGET
    member_budget_exceeded = len(members) > MEMBER_BUDGET
    return {
        "status": "over_budget" if byte_budget_exceeded or member_budget_exceeded else "ok",
        "bytes": len(header),
        "members": len(members),
        "byte_budget_exceeded": byte_budget_exceeded,
        "member_budget_exceeded": member_budget_exceeded,
        "duplicate_member_ordinals": duplicates,
    }


def emit(data, code):
    remaining = memoryview(data)
    try:
        while remaining:
            written = os.write(1, remaining)
            if written <= 0:
                return 2
            remaining = remaining[written:]
    except OSError:
        return 2
    return code


def main(args):
    if args in (["--help"], ["-h"]):
        return emit(b"Usage: python baggage_budget_audit.py HEADER\n", 0)
    try:
        path, = args
        check_path(path)
        report = audit(read_header(path))
        code = int(report["status"] == "over_budget")
    except (OSError, ValueError):
        report, code = {"status": "invalid"}, 2
    return emit(json.dumps(report, separators=(",", ":")).encode("ascii") + b"\n", code)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

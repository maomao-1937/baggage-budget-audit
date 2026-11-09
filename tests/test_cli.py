import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "baggage_budget_audit.py"
INVALID = {"status": "invalid"}


def load_subject():
    if not SCRIPT.is_file():
        raise AssertionError("CLI entry point is missing")
    spec = importlib.util.spec_from_file_location("baggage_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BaggageAuditTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.header = Path(directory.name) / "private-header.raw"

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *map(str, args)], capture_output=True, timeout=10,
        )

    def report(self, exit_code, *args):
        process = self.run_cli(*args)
        self.assertEqual(process.returncode, exit_code, process.stderr)
        self.assertEqual(process.stderr, b"")
        self.assertEqual(len(process.stdout.splitlines()), 1)
        self.assertNotIn(b"private", process.stdout.lower())
        return json.loads(process.stdout)

    def audit(self, data, exit_code):
        self.header.write_bytes(data)
        return self.report(exit_code, self.header)

    def test_ows_and_private_duplicate_ordinals(self):
        raw = (b"\t private-key \t= \tprivate=opaque%FF \t; mark \t; property = %3B%2C%25  ,"
               b"\tPrivate-key= ; tag= , private-key = %00 , private-key=\t")
        expected = {"status": "ok", "bytes": len(raw), "members": 4,
                    "byte_budget_exceeded": False, "member_budget_exceeded": False,
                    "duplicate_member_ordinals": [3, 4]}
        self.assertEqual(self.audit(raw, 0), expected)
        self.assertEqual(self.header.read_bytes(), raw)
        self.assertEqual(self.run_cli(self.header).stdout, self.run_cli(self.header).stdout)

    def test_token_keys_and_baggage_octets(self):
        token = b"!#$%&'*+-.^_`|~09AZaz"
        values = bytes(byte for byte in range(0x21, 0x7F) if byte not in b'"%,;\\')
        raw = token + b"=" + values + b"%FF%a0;" + token + b"="
        self.assertEqual(self.audit(raw, 0)["members"], 1)
        self.assertEqual(self.audit(b"x%2f=,x%2F=,x%2f=", 0)["duplicate_member_ordinals"], [3])
        self.assertEqual(self.audit(b"x==;x==;x", 0)["duplicate_member_ordinals"], [])

    def test_rejects_invalid_member_or_property_syntax(self):
        invalid = (
            b"", b"\t ", b"private=x,", b",private=x", b"x=, ,y=", b"private",
            b"=x", b"x y=z", b"x/y=z", b"x(y)=z", b"x=\"quoted\"", b"x=foo bar",
            b"x=foo\tbar", b"x=foo\\bar", b"x=foo\x7f", b"x=foo\x0b", b"x=\xff",
            b"x=\xc3\xa9", b"\xef\xbb\xbfx=1", b"x=\r\n", b"x=\n", b"baggage: x=1",
            b"x=1;", b"x=1;;p", b"x=1; =value", b"x=1;p=q; r s", b"x=1;p=\"value\"",
        )
        for raw in invalid:
            with self.subTest(raw=raw):
                self.assertEqual(self.audit(raw, 2), INVALID)

    def test_percent_sign_requires_two_hex_digits_in_every_value(self):
        for value in (b"%", b"%2", b"%2z", b"%z2", b"%%20", b"%+0"):
            for prefix in (b"private=", b"a=1;p="):
                with self.subTest(value=value, prefix=prefix):
                    self.assertEqual(self.audit(prefix + value, 2), INVALID)
        raw = b"a=%C0%AF%FF%aF%0d%0A%3D=;p=%00"
        self.assertEqual(self.audit(raw, 0)["bytes"], len(raw))

    def test_exact_member_and_grammar_ceilings(self):
        for count, status in ((64, 0), (65, 1), (180, 1), (181, 2)):
            with self.subTest(count=count):
                raw = b", ".join([b"key=; p; p2="] * count)
                report = self.audit(raw, status)
                if status == 2:
                    self.assertEqual(report, INVALID)
                else:
                    self.assertEqual(report["members"], count)
                    self.assertEqual(report["bytes"], len(raw))
                    self.assertEqual(report["member_budget_exceeded"], status == 1)
                    self.assertIs(report["byte_budget_exceeded"], False)
                    self.assertEqual(report["duplicate_member_ordinals"], list(range(2, count + 1)))

    def test_exact_byte_budget_and_file_limit(self):
        for size, status in ((8192, 0), (8193, 1), (262144, 1), (262145, 2)):
            with self.subTest(size=size):
                raw = b"a=x," + b" " * (size - 7) + b"b=\t"
                report = self.audit(raw, status)
                if status == 2:
                    self.assertEqual(report, INVALID)
                else:
                    self.assertEqual(report, {"status": "over_budget" if status else "ok",
                                             "bytes": size, "members": 2, "byte_budget_exceeded": bool(status),
                                             "member_budget_exceeded": False, "duplicate_member_ordinals": []})

    def test_both_budgets_and_validation_of_whole_header(self):
        raw = b"a=" + b"x" * 8192 + b",key=" * 64
        report = self.audit(raw, 1)
        self.assertTrue(report["byte_budget_exceeded"] and report["member_budget_exceeded"])
        self.assertEqual(self.audit(raw + b";bad=%GG", 2), INVALID)

    def test_help_argument_errors_and_unreadable_input(self):
        self.assertEqual(self.report(2), INVALID)
        self.assertEqual(self.report(2, self.header, "extra"), INVALID)
        self.assertEqual(self.report(2, self.header), INVALID)
        self.assertEqual(self.report(2, self.header.parent), INVALID)
        help_run = self.run_cli("--help")
        self.assertEqual((help_run.returncode, help_run.stderr), (0, b""))
        self.assertIn(b"baggage_budget_audit.py HEADER", help_run.stdout)

    def test_unsafe_paths_never_reach_stat_or_open(self):
        module = load_subject()
        paths = ("https://example.invalid/private", "file:///private", r"/\host\share",
                 r"\??\private", r"\Device\private", "/dir/../GLOBALROOT/private",
                 r"\dir/../SystemRoot\private", r"C:relative.raw", "file.raw:stream",
                 "C:/file.raw:stream", "parent/NUL .raw", "parent/LPT³.raw", "x.raw. ",
                 "x.raw/", "x\x00.raw", "-")
        for path in paths:
            with (
                self.subTest(path=path),
                patch.object(module.os, "stat", side_effect=AssertionError("stat called")),
                patch.object(module.os, "open", side_effect=AssertionError("open called")),
                patch.object(module, "emit", return_value=2) as emit,
            ):
                self.assertEqual(module.main([path]), 2)
                self.assertEqual(json.loads(emit.call_args.args[0]), INVALID)
        module.check_path(r"C:\ordinary\file.raw")

    def test_descriptor_rechecked_and_closed_when_invalid(self):
        module = load_subject()
        self.header.write_bytes(b"a=")
        for mode, size in ((stat.S_IFCHR, 0), (stat.S_IFREG, 262145)):
            with (
                self.subTest(mode=mode, size=size),
                patch.object(module.os, "fstat", return_value=SimpleNamespace(st_mode=mode, st_size=size)) as fstat,
                patch.object(module.os, "fdopen", side_effect=AssertionError("descriptor read")),
                patch.object(module, "emit", return_value=2) as emit,
            ):
                self.assertEqual(module.main([str(self.header)]), 2)
                self.assertEqual(json.loads(emit.call_args.args[0]), INVALID)
            with self.assertRaises(OSError):
                os.fstat(fstat.call_args.args[0])

    def test_fifo_fails_without_opening(self):
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.header)
            self.assertEqual(self.report(2, self.header), INVALID)
            return
        module = load_subject()
        with (
            patch.object(module.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFIFO, st_size=0)),
            patch.object(module.os, "open", side_effect=AssertionError("FIFO opened")),
            patch.object(module, "emit", return_value=2) as emit,
        ):
            self.assertEqual(module.main([str(self.header)]), 2)
            self.assertEqual(json.loads(emit.call_args.args[0]), INVALID)

    def test_closed_stdout_quiet_on_report_and_help(self):
        self.header.write_bytes(b"a=")
        for args in ((str(self.header),), ("--help",), ()):
            read_fd, write_fd = os.pipe()
            os.close(read_fd)
            with os.fdopen(write_fd, "wb") as broken:
                process = subprocess.run([sys.executable, "-B", str(SCRIPT), *args],
                                         stdout=broken, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual((process.returncode, process.stderr), (2, b""))


if __name__ == "__main__":
    unittest.main()

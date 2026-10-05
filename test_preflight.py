import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

import preflight as p


def archive(names=("readme.txt",), *, compression=0, extra=b"", comment=b""):
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression=compression) as z:
            z.comment = comment
            for name in names:
                info = zipfile.ZipInfo(name)
                info.compress_type = compression
                info.external_attr = (stat.S_IFDIR | 0o755) << 16 | 0x10 if name.endswith("/") else (stat.S_IFREG | 0o644) << 16
                info.extra = extra
                z.writestr(info, b"" if name.endswith("/") else b"synthetic data\n")
    return output.getvalue()


def change(data, location, fmt, value):
    result = bytearray(data)
    struct.pack_into(fmt, result, location, value)
    return bytes(result)


def central(data):
    return data.index(b"PK\x01\x02")


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "input.zip"

    def tearDown(self):
        self.temp.cleanup()

    def report(self, data):
        self.path.write_bytes(data)
        before = hashlib.sha256(self.path.read_bytes()).digest()
        result = p.inspect_archive(self.path)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)
        self.assertEqual(sorted(x.name for x in self.path.parent.iterdir()), ["input.zip"])
        return result

    def rules(self, names):
        report = self.report(archive(names))
        self.assertTrue(report["inspection_complete"], report)
        return {f["rule"]: f for f in report["findings"]}

    def rejected(self, data, reason):
        report = self.report(data)
        self.assertEqual(report, p.rejection(reason))

    def test_safe_names(self):
        self.assertEqual(self.report(archive(["docs/", "docs/readme.txt", ".config", "COM10", "NULL.txt", "report..txt"]))["status"], "no_name_findings")

    def test_empty_zip(self):
        self.assertEqual(self.report(archive([]))["member_count"], 0)

    def test_deflate(self):
        self.assertEqual(self.report(archive(compression=8))["status"], "no_name_findings")

    def test_duplicate_indices_and_raw_names(self):
        report = self.report(archive(["a", "b", "a"]))
        self.assertEqual(report["findings"], [{"rule": "DUPLICATE_MEMBER", "severity": "profile_error", "members": [0, 2], "path": "a"}])
        self.assertEqual([m["index"] for m in report["members"]], [0, 1, 2])
        self.assertEqual(report["members"][2]["name_bytes_hex"], "61")

    def test_ascii_case(self):
        self.assertEqual(self.rules(["Readme", "README"])["ASCII_CASE_COLLISION"]["members"], [0, 1])

    def test_implicit_directory_case(self):
        self.assertEqual(self.rules(["Dir/a", "dir/b"])["ASCII_CASE_COLLISION"]["path"], "dir")

    def test_file_directory_prefix(self):
        self.assertEqual(self.rules(["a", "a/b"])["FILE_DIRECTORY_CONFLICT"]["members"], [0, 1])

    def test_explicit_file_directory(self):
        self.assertIn("FILE_DIRECTORY_CONFLICT", self.rules(["a", "a/"]))

    def test_unrelated_prefix_is_safe(self):
        self.assertEqual(self.rules(["a", "ab/c"]), {})

    def test_trailing_dots_spaces_each_component(self):
        self.assertIn("TRAILING_DOT_OR_SPACE", self.rules(["dir. /a", "b "]))

    def test_devices_and_safe_near_matches(self):
        for name in ["NUL", "nul.txt", "COM¹.tar.gz", "LPT²", "d/aux.log", "con"]:
            with self.subTest(name=name):
                self.assertIn("RESERVED_DEVICE_NAME", self.rules([name]))
        self.assertEqual(self.rules(["COM0", "COM10", "AUXILIARY", "NULL", "lpt4x"]), {})

    def test_invalid_paths(self):
        for name in ["../x", "/x", "./x", "a//b"]:
            with self.subTest(name=name):
                self.assertIn("NON_PORTABLE_PATH", self.rules([name]))

    def test_reserved_characters(self):
        for name in ["C:x", "a\\b", "a?b", "a\x1bb"]:
            with self.subTest(name=name):
                self.assertIn("RESERVED_CHARACTER", self.rules([name]))

    def test_original_nul_not_zipinfo_truncation(self):
        data = archive(["aXb", "a"])
        data = data.replace(b"aXb", b"a\x00b")
        report = self.report(data)
        self.assertEqual(report["members"][0]["name"], "a\x00b")
        self.assertEqual(report["members"][0]["name_bytes_hex"], "610062")
        self.assertIn("RESERVED_CHARACTER", [f["rule"] for f in report["findings"]])
        self.assertNotIn("DUPLICATE_MEMBER", [f["rule"] for f in report["findings"]])

    def test_unicode_nfc_is_warning(self):
        finding = self.rules(["caf\u00e9.txt", "cafe\u0301.txt"])["UNICODE_NFC_SIMILARITY"]
        self.assertEqual(finding["severity"], "warning")
        self.assertEqual(finding["members"], [0, 1])

    def test_unicode_casefold_not_platform_claim(self):
        rules = self.rules(["Straße.txt", "STRASSE.txt"])
        self.assertEqual(rules["UNICODE_CASEFOLD_SIMILARITY"]["severity"], "warning")
        self.assertNotIn("ASCII_CASE_COLLISION", rules)

    def test_cp437_original_bytes(self):
        data = archive(["X"])
        c = central(data)
        data = bytearray(data)
        data[30] = data[c + 46] = 0x82
        report = self.report(bytes(data))
        self.assertEqual(report["members"][0]["name"], "é")
        self.assertEqual(report["members"][0]["name_bytes_hex"], "82")

    def test_invalid_utf8(self):
        data = bytearray(archive(["X"]))
        c = central(data)
        struct.pack_into("<H", data, 6, 0x800)
        struct.pack_into("<H", data, c + 8, 0x800)
        data[30] = data[c + 46] = 0xFF
        self.rejected(bytes(data), "invalid_name_encoding")

    def test_flags_rejected(self):
        for flags in [1, 8, 0x40, 0x1000]:
            data = archive()
            with self.subTest(flags=flags):
                self.rejected(change(data, central(data) + 8, "<H", flags), "unsupported_zip_flags")

    def test_zip64_sentinel(self):
        data = archive()
        self.rejected(change(data, len(data) - 12, "<H", 65535), "unsupported_multidisk")
        self.rejected(change(data, central(data) + 20, "<I", 0xFFFFFFFF), "unsupported_zip64")

    def test_zip64_extra(self):
        self.rejected(archive(extra=struct.pack("<HH", 1, 0)), "unsupported_extra_field")

    def test_unknown_or_alternate_name_extra(self):
        for tag in [0x7075, 0x6375, 0xCAFE]:
            self.rejected(archive(extra=struct.pack("<HH", tag, 0)), "unsupported_extra_field")

    def test_supported_timestamp_extra(self):
        self.assertEqual(self.report(archive(extra=b"\x55\x54\x01\x00\x00"))["status"], "no_name_findings")

    def test_malformed_extra(self):
        self.rejected(archive(extra=b"\x55\x54\x04\x00\x00"), "invalid_extra_field")

    def test_unsupported_compression(self):
        data = archive()
        self.rejected(change(data, central(data) + 10, "<H", 99), "unsupported_zip_features")

    def test_symlink(self):
        data = archive()
        self.rejected(change(data, central(data) + 38, "<I", (stat.S_IFLNK | 0o777) << 16), "unsupported_special_member")

    def test_local_name_mismatch(self):
        data = bytearray(archive())
        data[30] = ord("X")
        self.rejected(bytes(data), "local_central_name_mismatch")

    def test_local_metadata_mismatch(self):
        self.rejected(change(archive(), 14, "<I", 123), "local_central_mismatch")

    def test_overlapping_offsets(self):
        data = archive(["a", "b"])
        second = data.index(b"PK\x01\x02", central(data) + 1)
        self.rejected(change(data, second + 42, "<I", 0), "unsupported_record_layout")

    def test_prepended_data(self):
        self.rejected(b"junk" + archive(), "unsupported_record_layout")

    def test_trailing_data(self):
        self.rejected(archive() + b"junk", "invalid_or_ambiguous_end_record")

    def test_comment_signature(self):
        self.assertEqual(self.report(archive(comment=b"hello PK\x05\x06 world"))["status"], "no_name_findings")

    def test_every_truncation_rejected(self):
        data = archive()
        for end in range(len(data)):
            self.assertEqual(self.report(data[:end])["status"], "rejected", end)

    def test_no_separate_payload_read(self):
        data = archive(["a"])
        start = 31
        end = central(data)
        class Guard(io.BytesIO):
            def read(self, length=-1):
                # Tail EOCD search is bounded but can include payload bytes.
                if self.tell() == start and length == end - start:
                    raise AssertionError("payload read")
                return super().read(length)
        self.assertEqual(len(p.read_members(Guard(data), len(data))), 1)

    def test_payload_integrity_is_explicitly_outside_scope(self):
        data = bytearray(archive(["a"]))
        data[31] ^= 1
        self.assertEqual(self.report(bytes(data))["status"], "no_name_findings")

    def test_size_limit_before_reads(self):
        class NoRead:
            def seek(self, *args):
                raise AssertionError("must reject before I/O")
        with self.assertRaises(p.Rejected) as raised:
            p.read_members(NoRead(), p.MAX_ARCHIVE + 1)
        self.assertEqual(raised.exception.code, "archive_size_limit")

    def test_count_limit_before_central_read(self):
        data = archive()
        data = change(data, len(data) - 14, "<H", p.MAX_MEMBERS + 1)
        data = change(data, len(data) - 12, "<H", p.MAX_MEMBERS + 1)
        self.rejected(data, "member_count_limit")

    def test_metadata_limit_before_central_read(self):
        data = archive()
        self.rejected(change(data, len(data) - 10, "<I", p.MAX_METADATA + 1), "metadata_size_limit")

    def test_depth_and_name_limits(self):
        self.rejected(archive(["a/" * p.MAX_DEPTH + "b"]), "path_depth_limit")
        self.rejected(archive(["a" * (p.MAX_NAME + 1)]), "member_name_limit")

    def test_actual_count_not_only_declared(self):
        data = archive(["a", "b"])
        data = change(data, len(data) - 14, "<H", 1)
        data = change(data, len(data) - 12, "<H", 1)
        self.rejected(data, "invalid_member_count")

    def test_output_bound_fails_closed(self):
        with patch.object(p, "MAX_OUTPUT", 64):
            self.rejected(archive(), "report_size_limit")

    def test_finding_count_bound(self):
        with patch.object(p, "MAX_FINDINGS", 1):
            self.rejected(archive(["NUL.", "a?b"]), "finding_count_limit")

    def test_regular_file_only(self):
        self.assertEqual(p.inspect_archive(self.path.parent)["status"], "rejected")
        self.assertEqual(p.inspect_archive(self.path)["status"], "rejected")

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "platform has no O_NOFOLLOW")
    def test_symlink_input_rejected(self):
        target = self.path.parent / "target.zip"
        target.write_bytes(archive())
        self.path.symlink_to(target)
        self.assertEqual(p.inspect_archive(self.path)["status"], "rejected")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no FIFO")
    def test_fifo_never_blocks(self):
        os.mkfifo(self.path)
        self.assertEqual(p.inspect_archive(self.path)["reason"], "not_regular_file")

    def test_cli_status_json_and_escaped_controls(self):
        script = Path(__file__).with_name("preflight.py")
        for data, exit_code, status in [(archive(), 0, "no_name_findings"), (archive(["a\x1bb"]), 1, "name_findings"), (b"bad", 2, "rejected")]:
            self.path.write_bytes(data)
            result = subprocess.run([sys.executable, "-B", str(script), str(self.path)], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, exit_code, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], status)
            self.assertEqual(result.stderr, b"")
            self.assertNotIn(b"\x1b", result.stdout)
            self.assertNotIn(str(self.path).encode(), result.stdout)
            self.assertEqual(self.path.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()

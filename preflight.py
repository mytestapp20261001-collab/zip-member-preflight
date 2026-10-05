"""Bounded, read-only ZIP member-name delivery checks. Python standard library."""
import argparse
import json
import os
import re
import stat
import struct
import sys
import unicodedata

PROFILE = "conservative-delivery-v1"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_METADATA = 1024 * 1024
MAX_MEMBERS = 2000
MAX_NAME = 1024
MAX_DEPTH = 32
MAX_FINDINGS = 5000
MAX_OUTPUT = 1024 * 1024
EOCD = struct.Struct("<4s4H2IH")
CENTRAL = struct.Struct("<4s6H3I5H2I")
LOCAL = struct.Struct("<4s5H3I2H")
DEVICE = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.I)
BAD_CHAR = re.compile(r'[<>:"\\|?*\x00-\x1f]')


class Rejected(Exception):
    """Incomplete inspection; never a no-findings verdict."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def reject(condition, code):
    if condition:
        raise Rejected(code)


def extra_fields(data):
    """Validate framing, refusing alternate names and ZIP64 interpretation."""
    position = 0
    while position < len(data):
        reject(position + 4 > len(data), "invalid_extra_field")
        tag, size = struct.unpack_from("<HH", data, position)
        position += 4
        reject(position + size > len(data), "invalid_extra_field")
        # Only common timestamp / Unix UID metadata is admitted; no name override.
        reject(tag not in (0x5455, 0x000A, 0x7875), "unsupported_extra_field")
        position += size


def read_members(stream, size):
    """Inspect bounded ZIP metadata; never decompress or inspect member content.

    The bounded end-record search can incidentally read compressed payload bytes.
    """
    reject(size > MAX_ARCHIVE, "archive_size_limit")
    reject(size < EOCD.size, "invalid_end_record")
    tail_size = min(size, EOCD.size + 65535)
    stream.seek(size - tail_size)
    tail = stream.read(tail_size)
    reject(len(tail) != tail_size, "input_changed_or_truncated")
    # An EOCD signature inside a comment must not hide a valid end record.
    candidates = []
    position = tail.find(b"PK\x05\x06")
    while position >= 0:
        if position + EOCD.size <= len(tail):
            record = EOCD.unpack_from(tail, position)
            if position + EOCD.size + record[-1] == len(tail):
                candidates.append((size - tail_size + position, record))
        position = tail.find(b"PK\x05\x06", position + 1)
    reject(len(candidates) != 1, "invalid_or_ambiguous_end_record")
    end_offset, end = candidates[0]
    _, disk, central_disk, disk_count, count, central_size, central_offset, _ = end
    reject(disk or central_disk or disk_count != count, "unsupported_multidisk")
    reject(count == 65535 or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF,
           "unsupported_zip64")
    reject(count > MAX_MEMBERS, "member_count_limit")
    reject(central_size > MAX_METADATA, "metadata_size_limit")
    reject(central_offset + central_size != end_offset, "unsupported_record_layout")
    reject(count * CENTRAL.size > central_size, "invalid_member_count")
    stream.seek(central_offset)
    data = stream.read(central_size)
    reject(len(data) != central_size, "input_changed_or_truncated")
    position = 0
    records = []
    for index in range(count):
        reject(position + CENTRAL.size > len(data), "invalid_central_record")
        h = CENTRAL.unpack_from(data, position)
        reject(h[0] != b"PK\x01\x02", "invalid_central_record")
        _, made, needed, flags, method, time, date, crc, packed, unpacked, name_len, extra_len, comment_len, start_disk, internal, external, offset = h
        reject(needed > 20 or method not in (0, 8), "unsupported_zip_features")
        reject(flags & ~0x806 or (method == 0 and flags & 6), "unsupported_zip_flags")
        reject(start_disk != 0, "unsupported_multidisk")
        reject(0xFFFFFFFF in (packed, unpacked, offset), "unsupported_zip64")
        reject(name_len == 0 or name_len > MAX_NAME, "member_name_limit")
        record_end = position + CENTRAL.size + name_len + extra_len + comment_len
        reject(record_end > len(data), "invalid_central_record")
        raw = data[position + CENTRAL.size:position + CENTRAL.size + name_len]
        extra = data[position + CENTRAL.size + name_len:position + CENTRAL.size + name_len + extra_len]
        extra_fields(extra)
        try:
            name = raw.decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeDecodeError:
            raise Rejected("invalid_name_encoding") from None
        # Keep original bytes and decoded NULs; never use ZipInfo's sanitized name.
        mode = external >> 16
        reject(made >> 8 not in (0, 3), "unsupported_creator_system")
        reject(made >> 8 == 3 and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR),
               "unsupported_special_member")
        is_dir = name.endswith("/")
        reject(bool(external & 0x10) and not is_dir, "inconsistent_directory_metadata")
        reject(made >> 8 == 3 and stat.S_IFMT(mode) == stat.S_IFDIR and not is_dir,
               "inconsistent_directory_metadata")
        reject(made >> 8 == 3 and stat.S_IFMT(mode) == stat.S_IFREG and is_dir,
               "inconsistent_directory_metadata")
        reject(is_dir and (packed or unpacked), "unsupported_directory_payload")
        reject(method == 0 and packed != unpacked, "inconsistent_stored_size")
        records.append({"index": index, "name": name, "raw": raw, "directory": is_dir,
                        "offset": offset, "packed": packed, "unpacked": unpacked,
                        "needed": needed, "flags": flags, "method": method,
                        "time": time, "date": date, "crc": crc})
        position = record_end
    reject(position != central_size, "invalid_member_count")
    # Check names in both headers without reading or inflating compressed bodies.
    expected_offset = 0
    metadata_used = central_size
    for member in sorted(records, key=lambda m: m["offset"]):
        reject(member["offset"] != expected_offset, "unsupported_record_layout")
        reject(member["offset"] + LOCAL.size > central_offset, "invalid_local_record")
        stream.seek(member["offset"])
        header = stream.read(LOCAL.size)
        reject(len(header) != LOCAL.size, "input_changed_or_truncated")
        local = LOCAL.unpack(header)
        reject(local[0] != b"PK\x03\x04", "invalid_local_record")
        _, needed, flags, method, time, date, crc, packed, unpacked, name_len, extra_len = local
        reject([needed, flags, method, time, date, crc, packed, unpacked] !=
               [member[k] for k in ("needed", "flags", "method", "time", "date", "crc", "packed", "unpacked")],
               "local_central_mismatch")
        reject(name_len != len(member["raw"]), "local_central_name_mismatch")
        metadata_used += LOCAL.size + name_len + extra_len
        reject(metadata_used > MAX_METADATA, "metadata_size_limit")
        expected_offset = member["offset"] + LOCAL.size + name_len + extra_len + packed
        reject(expected_offset > central_offset, "invalid_member_extent")
        name = stream.read(name_len)
        extra = stream.read(extra_len)
        reject(name != member["raw"], "local_central_name_mismatch")
        reject(len(extra) != extra_len, "input_changed_or_truncated")
        extra_fields(extra)
    reject(expected_offset != central_offset, "unsupported_record_layout")
    return records


def ascii_fold(value):
    return value.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))


def inspect_names(members):
    findings = []

    def add(rule, indices, path=None, severity="profile_error"):
        reject(len(findings) >= MAX_FINDINGS, "finding_count_limit")
        finding = {"rule": rule, "severity": severity, "members": sorted(set(indices))}
        if path is not None:
            finding["path"] = path
        findings.append(finding)

    exact = {}
    nodes = {}
    nfc_nodes = {}
    fold_nodes = {}
    for member in members:
        index, name = member["index"], member["name"]
        exact.setdefault(name, []).append(index)
        body = name[:-1] if member["directory"] else name
        parts = body.split("/")
        reject(len(parts) > MAX_DEPTH, "path_depth_limit")
        if not body or any(p in ("", ".", "..") for p in parts):
            add("NON_PORTABLE_PATH", [index])
        if BAD_CHAR.search(body):
            add("RESERVED_CHARACTER", [index])
        if any(p.endswith((" ", ".")) for p in parts):
            add("TRAILING_DOT_OR_SPACE", [index])
        if any(DEVICE.match(p) for p in parts):
            add("RESERVED_DEVICE_NAME", [index])
        # Invalid components remain unmodified in the report. Never invent a repair.
        for length in range(1, len(parts) + 1):
            path = "/".join(parts[:length])
            kind = "directory" if length < len(parts) or member["directory"] else "file"
            node = (path, kind, index)
            nodes.setdefault(ascii_fold(path), []).append(node)
            nfc_nodes.setdefault(unicodedata.normalize("NFC", path), []).append(node)
            fold_nodes.setdefault(path.casefold(), []).append(node)
    for name, indices in sorted(exact.items()):
        if len(indices) > 1:
            add("DUPLICATE_MEMBER", indices, name)
    for key, group in sorted(nodes.items()):
        indices = [n[2] for n in group]
        if len({n[0] for n in group}) > 1:
            add("ASCII_CASE_COLLISION", indices, key)
        if len({n[1] for n in group}) > 1:
            add("FILE_DIRECTORY_CONFLICT", indices, key)
    for rule, groups in (("UNICODE_NFC_SIMILARITY", nfc_nodes),
                         ("UNICODE_CASEFOLD_SIMILARITY", fold_nodes)):
        for key, group in sorted(groups.items()):
            paths = {n[0] for n in group}
            if len(paths) > 1 and (rule != "UNICODE_CASEFOLD_SIMILARITY" or
                                   len({ascii_fold(p) for p in paths}) > 1):
                add(rule, [n[2] for n in group], key, "warning")
    return findings


def rejection(code):
    return {"schema": 1, "profile": PROFILE, "status": "rejected", "reason": code,
            "inspection_complete": False}


def inspect_archive(path):
    """Read one explicitly supplied local regular file; never writes or uploads."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) |
                             getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            before = os.fstat(stream.fileno())
            reject(not stat.S_ISREG(before.st_mode), "not_regular_file")
            members = read_members(stream, before.st_size)
            after = os.fstat(stream.fileno())
            reject((before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                   (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "input_changed")
        findings = inspect_names(members)
        report = {"schema": 1, "profile": PROFILE,
                  "status": "name_findings" if findings else "no_name_findings",
                  "inspection_complete": True, "member_count": len(members),
                  "unicode_version": unicodedata.unidata_version,
                  "members": [{"index": m["index"], "name": m["name"],
                               "name_bytes_hex": m["raw"].hex(), "directory": m["directory"]}
                              for m in members], "findings": findings}
        reject(len(encode_report(report)) > MAX_OUTPUT, "report_size_limit")
        return report
    except Rejected as error:
        return rejection(error.code)
    except (OSError, ValueError):
        return rejection("unreadable_input")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def encode_report(report):
    # ASCII escaping prevents member-name terminal controls from being executed.
    return (json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="explicit local ZIP path; never extracted or modified")
    args = parser.parse_args()
    report = inspect_archive(args.archive)
    sys.stdout.buffer.write(encode_report(report))
    return {"no_name_findings": 0, "name_findings": 1, "rejected": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())

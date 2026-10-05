# ZIP member preflight

Find conflicting member names before handing off a ZIP export. This small Python standard-library CLI reports original names, zero-based member indices and stable rule IDs. It reads the explicitly supplied local archive and never extracts, renames, repairs or uploads it.

The initial scope is **Python 3.12 / 3.13 on Linux**, a declared conservative delivery profile and ordinary single-disk stored/Deflate ZIPs. There is no package installation, account or runtime network access. This is a filename review aid, not a ZIP security scanner or an exact Windows/macOS filesystem emulator.

## Run

```sh
python -B preflight.py /path/to/export.zip
python -B demo.py
python -B -m unittest -v
```

Replace `/path/to/export.zip` with a local file you are authorized to inspect. `demo.py` creates and removes two small synthetic archives in its own temporary directory. It shows a conflicting export and an adjusted export; it does not rewrite the input to the CLI.

The CLI prints one ASCII-escaped JSON report to stdout:

- Exit **0**, `no_name_findings`: all declared checks completed without name findings
- Exit **1**, `name_findings`: profile errors or conservative Unicode warnings require review
- Exit **2**, `rejected`: unsupported, unreadable, inconsistent or resource-limited input; inspection did not complete. Argument errors also exit 2 and print usage to stderr

Never interpret exit 0 as proof that an archive is safe, extractable, complete, uncorrupted or compatible with every recipient. Rejection is not a name-check pass. A Unicode warning is not proof of an actual filesystem collision.

For an archive with `Readme` and `README`, a finding is:

```json
{"members":[0,1],"path":"readme","rule":"ASCII_CASE_COLLISION","severity":"profile_error"}
```

The full report contains `schema: 1`, `profile: "conservative-delivery-v1"`, `inspection_complete`, `member_count`, the Python Unicode database version, `members` and `findings`. Each member preserves its original decoded name and `name_bytes_hex`; duplicates retain their distinct indices. Names use the ZIP UTF-8 flag or CP437 fallback, never guessed legacy encodings. NUL bytes remain visible in the report rather than being silently truncated by a normalized path API.

## The declared profile

Profile errors:

- `DUPLICATE_MEMBER`: the same full decoded name occurs more than once, including repeated explicit directory entries
- `ASCII_CASE_COLLISION`: two spellings of a full path or ancestor differ only in ASCII A–Z casing. Implicit directories count: `Dir/a` and `dir/b` are flagged
- `FILE_DIRECTORY_CONFLICT`: a file and an explicit or implicit directory share an ASCII-folded path, such as `assets` and `assets/icon.txt`
- `NON_PORTABLE_PATH`: empty, leading-slash, repeated-slash, `.` or `..` path components
- `RESERVED_CHARACTER`: a component contains `< > : " \ | ? *`, NUL or another ASCII control in 1–31
- `TRAILING_DOT_OR_SPACE`: a component ends in an ASCII space or period
- `RESERVED_DEVICE_NAME`: a component is a case-insensitive CON, PRN, AUX, NUL, COM1–9 or LPT1–9 name, including superscript ¹/²/³ and an immediately following extension

Separate warnings:

- `UNICODE_NFC_SIMILARITY`: differently spelled paths/ancestors become equal under NFC
- `UNICODE_CASEFOLD_SIMILARITY`: Python full casefold makes them equal beyond the ASCII check

These are independent comparison rules, not a combined normalization recipe. The report does not remove trailing characters, repair components, merge names, or simulate a destination extractor. For example, `Straße` and `STRASSE` produce a conservative casefold warning; that does not establish that NTFS treats them as equal. Unicode behavior is identified by the report's `unicode_version`.

`path` is the comparison key or original duplicate name. `members` includes all contributing archive-member indices; ancestor findings can include multiple descendants of one spelling. Per-member invalid-name findings omit `path`. Stable ordering makes reports suitable for explicit CI review.

## Supported input and resource boundaries

The reader checks bounded central and local-header metadata directly, so raw member names are available before any path normalization. It does not instantiate an unbounded ZIP parser or decompress member bodies. The end-record search reads at most 65,557 bytes; that suffix may incidentally contain compressed payload bytes, which are not interpreted or output.

Limits are fixed in this first version:

- Actual archive size: 64 MiB; regular local files only
- Declared and parsed members: 2,000
- Central directory plus inspected local-header metadata: 1 MiB
- Name bytes per member: 1,024; path components: 32
- Findings: 5,000; serialized report: 1 MiB

Size/count/central-directory limits are checked before reading or allocating the corresponding metadata. Local metadata and emitted findings are also bounded. A limit failure returns `rejected`, not a partial clean report. Do not edit limits upward without reviewing memory, work and output bounds.

The admitted layout has contiguous local records from byte zero, then the central directory, then one unambiguous end record and its optional comment. Central and local names and relevant header fields must agree. Empty archives and ordinary directory entries are supported. Allowed creators are DOS and Unix; compression is stored or Deflate. UTF-8 and Deflate-option flags are supported. Only the framed timestamp/UID extra fields `0x5455`, `0x000A` and `0x7875` are admitted; their values are not interpreted.

**Rejected as outside this implementation:** ZIP64, multiple disks, encryption, streaming data descriptors, self-extracting/prepended data, trailing data, gaps/overlapping members, alternate-name/unknown extra fields, unsupported methods/flags/creators and symlink/special-file members. Valid ZIPs using these features may be rejected. Use an appropriate existing archive tool instead of interpreting rejection as corruption.

CRC and compressed content are deliberately not checked. A corrupted payload can still return `no_name_findings`. No extraction safety, malware, zip-bomb, content, permissions, maximum destination path, 8.3 alias, exact platform normalization or recipient application compatibility claim is made. Filename metadata itself can be sensitive: reports contain it, so keep reports local unless separately authorized to share them. The program has no telemetry or network code.

Open the file while it is stable. The reader compares size/mtime/ctime before and after inspection, but this is not a snapshot or protection against a concurrent adversarial writer. On systems with `O_NOFOLLOW`, final-component symlink inputs are rejected; this is not a sandbox or a promise about parent path components. Linux is the tested platform.

## Use in a repair workflow

Review the reported members and the recipient's actual requirements. Change the authorized export source or packaging policy, generate a new archive, and rerun the same checks plus the real delivery test. Do not auto-rename collisions: deciding which distinct files to retain or merge belongs to the application/user. For programmatic use, `inspect_archive(path)` returns the same dictionary; `encode_report(report)` uses terminal-safe ASCII escaping.

Tests use generated synthetic archives, exact expected groups and indices, malformed metadata, NULs, Unicode near-matches, limit checks and a deliberately corrupted payload illustrating the coverage limit. They verify unchanged input bytes and the CLI's three outcomes. Mechanical tests are not evidence of independent adoption or complete cross-platform portability.

## Sources and related tools

- [Microsoft filename rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file) describe naming restrictions and filesystem/API differences
- [PKWARE APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), sections 4.3–4.6, defines the ZIP record structure; this project implements only the subset above
- [Python zipfile](https://docs.python.org/3/library/zipfile.html) provides general archive operations; use maintained archive libraries for extraction
- [Pure](https://github.com/ronomon/pure) checks ZIP format/security anomalies
- [zipkirei](https://github.com/yuk7/zipkirei) repairs metadata and has a dry-run preview
- [Go's module ZIP package](https://github.com/golang/mod/blob/master/zip/zip.go) already checks name collisions under its module-specific contract

This project's narrow contribution is a read-only indexed member-name report for general export review. It makes no claim to invent collision checking or replace those tools. Initial scope stays small; new formats and broader archive validation are not planned by this release.

## Optional creator invitation

This utility is made by the creator of [MyTest](https://mytest.app). If you want a separate game, the [private bot workshop](https://mytest.app/bot-workshop) lets you choose four rock-paper-scissors rules and inspect up to 20 hands per run. You can change rules, rerun, keep a rule card yourself or leave whenever you like. The scripted bot is not an independent AI. This is an optional promotional invitation: skip it freely, with no visit, account, play or feedback required for the engineering task. No productivity benefit is claimed.

"""Stack-based crash deduplication.

Faithful Python port of the crash-log parsing logic in CRS-multilang
``uniafl/src/executor/executor.rs`` — specifically ``parse_libfuzzer_crash_log``,
``parse_jazzer_crash_log``, ``parse_jazzer_timeout_log``, ``parse_dedup_tokens``,
``filter_valid_paths_from_bytes`` and ``filter_address_in_jazzer_log``.

Given the raw stderr of a crashing harness run, :func:`crash_signature` produces a
normalized byte string that identifies the crash by its *call stack* (mirroring
``Executor::run_pov``: libFuzzer parse → Jazzer parse → Jazzer-timeout parse →
``EMPTY_CRASH_CALLSTACK`` fallback). Two crashes with the same signature are
considered duplicates.

:func:`dedup_key` derives the hashable dedup key from a signature. On top of the
faithful port it strips nondeterministic hex addresses (load addresses vary with
ASLR) and collapses per-line whitespace, so the *same* call stack deduplicates
regardless of address-space layout. This only ever merges crashes the reference
would already consider the same stack site — it never splits them — keeping the
behaviour faithful while robust to environments where ASLR is not disabled.
"""

from __future__ import annotations

import hashlib
import re

# Sentinels, byte-for-byte identical to executor.rs.
DEFAULT_TIMEOUT_LOG = b"EMPTY TIMEOUT LOG"
EMPTY_CRASH_CALLSTACK = b"EMPTY_CRASH_CALLSTACK"


def _find(hay: bytes, needle: bytes, start: int = 0) -> int | None:
    """First index of ``needle`` in ``hay`` at/after ``start`` (None if absent).

    Mirrors ``utils::find_subarr``; an empty needle matches at ``start``.
    """
    idx = hay.find(needle, start)
    return None if idx < 0 else idx


def _after(cur: bytes, key: bytes) -> bytes | None:
    """Return the slice *after* the first occurrence of ``key`` (None if absent).

    Mirrors the ``get_subarr!`` macro (``&cur[from + key.len()..]``).
    """
    idx = cur.find(key)
    if idx < 0:
        return None
    return cur[idx + len(key):]


# --------------------------------------------------------------------------- #
# libFuzzer / ASAN (C / C++ / Rust / Go)
# --------------------------------------------------------------------------- #
def _extract_path_from_line(line: str) -> str | None:
    """Port of ``extract_path_from_line``.

    A symbolized frame looks like ``#0 0xADDR in func /path/file.c:10:5``: exactly
    five whitespace tokens whose last token is an absolute path. Returns the path
    with the ``:line:col`` suffix stripped, else None.
    """
    tokens = line.split()
    if len(tokens) == 5:
        last = tokens[-1]
        if last.startswith("/"):
            return last.split(":")[0]
    return None


def _filter_valid_paths_from_bytes(data: bytes) -> bytes | None:
    """Port of ``filter_valid_paths_from_bytes``.

    Keeps only renumbered stack-frame lines (``#0``, ``#1`` …) that carry a valid
    absolute path outside ``/src/llvm-project``, renumbering them consecutively.
    """
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None

    # Emulate Rust str::lines(): split on '\n' only, strip a single trailing
    # '\r' per line, and drop the final empty segment produced by a trailing
    # newline. Python str.splitlines() would also split on \v \f \x1c-\x1e NEL
    # U+2028/9 and bare \r, diverging from the reference.
    parts = s.split("\n")
    if parts and parts[-1] == "":
        parts.pop()

    out_lines: list[str] = []
    expected_index = 0
    for raw in parts:
        line = raw[:-1] if raw.endswith("\r") else raw
        tokens = line.split()
        if not tokens:
            continue
        first = tokens[0]
        # `first[1:].chars().all(is_digit(10))` — ASCII digits only (Python's
        # str.isdigit() also accepts Unicode digits). all() over an empty string
        # is True in Rust, so a bare "#" also passes (matched intentionally).
        rest = first[1:]
        if first.startswith("#") and all(c in "0123456789" for c in rest):
            path = _extract_path_from_line(line)
            if path is not None and not path.startswith("/src/llvm-project"):
                new_line = line.replace(first, f"#{expected_index}", 1)
                out_lines.append(new_line)
                expected_index += 1

    if not out_lines:
        return None
    return "\n".join(out_lines).encode("utf-8")


def parse_libfuzzer_crash_log(log: bytes, parse_err_head: bool) -> bytes | None:
    """Port of ``parse_libfuzzer_crash_log``.

    Extracts the crash call stack: from the first ``#0`` frame up to and including
    the ``LLVMFuzzerTestOneInput`` frame, then normalizes via
    :func:`_filter_valid_paths_from_bytes`.
    """
    if parse_err_head:
        frm: int | None = 0
    else:
        frm = _find(log, b"==ERROR: ")
        if frm is None:
            return None
    cur = log[frm:]

    frm = _find(cur, b"    #0 ")
    if frm is None:
        return None
    cur = cur[frm:]

    last = _find(cur, b" in LLVMFuzzerTestOneInput")
    if last is None:
        return None
    nl = _find(cur[last:], b"\n")
    if nl is None:
        return None
    last = last + nl
    return _filter_valid_paths_from_bytes(cur[:last])


def parse_dedup_tokens(log: bytes) -> bytes | None:
    """Port of ``parse_dedup_tokens`` (sanitizer ``DEDUP_TOKEN:`` lines, sorted)."""
    key = b"DEDUP_TOKEN: "
    tokens: list[bytes] = []
    cur = log
    while True:
        frm = cur.find(key)
        if frm < 0:
            break
        cur = cur[frm + len(key):]
        to = cur.find(b"\n")
        if to >= 0:
            tokens.append(cur[:to])
            cur = cur[to:]
    if not tokens:
        return None
    tokens.sort()
    return b"\n".join(tokens)


# --------------------------------------------------------------------------- #
# Jazzer (JVM)
# --------------------------------------------------------------------------- #
def filter_address_in_jazzer_log(log: bytes) -> bytes:
    """Port of ``filter_address_in_jazzer_log`` — drop any line containing ``0x``."""
    if log == DEFAULT_TIMEOUT_LOG:
        return log
    out = bytearray()
    for line in log.split(b"\n"):
        if line.find(b"0x") < 0:
            out += line
            out += b"\n"
    return bytes(out)


def parse_jazzer_crash_log(log: bytes) -> bytes | None:
    """Port of ``parse_jazzer_crash_log``.

    Extracts the Java exception stack between ``== Java Exception:`` and either
    ``Caused by:`` or the libFuzzer crashing-input banner, stripping addresses.
    """
    cur = _after(log, b"== Java Exception:")
    if cur is None:
        return None
    frm = cur.find(b"\tat")
    if frm < 0:
        return None
    cur = cur[frm:]
    caused = cur.find(b"Caused by:")
    if caused >= 0:
        cur = cur[:caused]
    libf = cur.find(b"== libFuzzer crashing input ==")
    if libf >= 0:
        return filter_address_in_jazzer_log(cur[:libf])
    return filter_address_in_jazzer_log(cur)


def parse_jazzer_timeout_stack(log: bytes) -> bytes | None:
    """Port of ``parse_jazzer_timeout_stack`` — main-thread stack on hang."""
    cur = _after(log, b"Thread[main")
    if cur is None:
        return None
    cur = _after(cur, b"\n")
    if cur is None:
        return None
    last = cur.find(b"\n\n")
    if last < 0:
        return None
    return filter_address_in_jazzer_log(cur[:last])


def parse_jazzer_timeout_log(log: bytes) -> bytes | None:
    """Port of ``parse_jazzer_timeout_log``."""
    stack = parse_jazzer_timeout_stack(log)
    if stack is not None:
        return stack
    if log.find(b"ERROR: libFuzzer: timeout after") >= 0:
        return DEFAULT_TIMEOUT_LOG
    return None


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #
def crash_signature(stderr: bytes) -> bytes:
    """Canonical stack-based crash signature for a crash's raw stderr.

    Mirrors ``Executor::run_pov``: libFuzzer parse (with ``parse_err_head=True``)
    → Jazzer parse → Jazzer-timeout parse → ``EMPTY_CRASH_CALLSTACK`` fallback.
    Tries every parser regardless of language, exactly like the reference, so a
    single code path handles C/C++/Rust/Go and JVM.
    """
    sig = parse_libfuzzer_crash_log(stderr, True)
    if sig is None:
        sig = parse_jazzer_crash_log(stderr)
    if sig is None:
        sig = parse_jazzer_timeout_log(stderr)
    if sig is None:
        sig = EMPTY_CRASH_CALLSTACK
    return sig


_ADDR_RE = re.compile(rb"0x[0-9a-fA-F]+")


def dedup_key(signature: bytes) -> str:
    """Hashable dedup key for a signature (SHA-1 hex).

    Normalizes standalone hex address tokens (ASLR load addresses) and collapses
    per-line whitespace before hashing, so the same call stack maps to one key
    irrespective of address-space layout. Only whole whitespace-delimited tokens
    that are entirely a hex address are normalized — a ``0x``-looking substring
    inside a source path or identifier is left intact, so distinct call sites are
    never wrongly merged. See module docstring.
    """
    norm_lines = []
    for line in signature.split(b"\n"):
        tokens = [b"0x" if _ADDR_RE.fullmatch(tok) else tok for tok in line.split()]
        norm_lines.append(b" ".join(tokens))
    norm = b"\n".join(norm_lines)
    return hashlib.sha1(norm).hexdigest()


def is_empty_signature(signature: bytes) -> bool:
    """True if the signature carries no usable stack information."""
    return signature in (EMPTY_CRASH_CALLSTACK, DEFAULT_TIMEOUT_LOG, b"")


# Markers that distinguish a real sanitizer/Jazzer/signal crash from a harness
# that merely exited non-zero on bad input (e.g. a config parser rejecting input,
# which libFuzzer reports as "fuzz target exited" — not a vulnerability).
_REAL_CRASH_MARKERS = (
    b"AddressSanitizer",
    b"LeakSanitizer",
    b"ThreadSanitizer",
    b"MemorySanitizer",
    b"UndefinedBehaviorSanitizer",
    b"runtime error:",                  # UBSAN
    b"ERROR: libFuzzer: deadly signal", # SEGV/ABRT/FPE caught by libFuzzer
    b"ERROR: libFuzzer: timeout",
    b"ERROR: libFuzzer: out-of-memory",
    b"== Java Exception:",              # Jazzer
    b"FuzzerSecurityIssue",             # Jazzer security hooks
    b"SUMMARY: ",                       # sanitizer summary line
)


def is_real_crash(crash_log: bytes) -> bool:
    """True if the harness output indicates a real sanitizer/Jazzer/signal crash.

    A non-zero exit alone is not enough: harnesses such as a config parser
    legitimately ``exit()`` on malformed input, which libFuzzer surfaces as
    "fuzz target exited" — a false positive, not a vulnerability. Sanitizer
    builds always emit one of these markers on a genuine memory/security fault,
    so requiring a marker filters false positives without dropping real bugs.
    """
    return any(m in crash_log for m in _REAL_CRASH_MARKERS)

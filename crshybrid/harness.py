"""Run inputs against an oss-fuzz harness binary.

The orchestrator runs inside the target image (``FROM target_base_image``), so it
has the full target runtime — it can execute the compiled libFuzzer / Jazzer
harnesses directly, both for continuous fuzzing and for single-input crash
verification (no runner sidecar needed).
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("crshybrid.harness")

# Reproduce-friendly sanitizer options.
# NOTE: deliberately *no* strip_path_prefix — the stack-based dedup parser keys on
# absolute source paths (frames whose last token starts with '/'); stripping the
# prefix would drop every frame and collapse all crashes to one signature.
DEFAULT_ASAN_OPTIONS = (
    "abort_on_error=1:symbolize=1:detect_leaks=0:handle_abort=1:handle_segv=1:"
    "handle_sigill=1:handle_sigfpe=1:handle_sigbus=1:allocator_may_return_null=1:"
    "print_scariness=1:dedup_token_length=3"
)
DEFAULT_UBSAN_OPTIONS = "symbolize=1:print_stacktrace=1:halt_on_error=1"

# oss-fuzz helper artifacts that live in /out alongside real harness binaries.
_NON_HARNESS_NAMES = {
    "llvm-symbolizer",
    "jazzer_driver",
    "jazzer_agent_deploy.jar",
    "jazzer_api_deploy.jar",
    "jazzer_junit.jar",
    "sancov",
    "afl-fuzz",
    "afl-showmap",
}


@dataclass
class RunResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    launch_failed: bool = False

    @property
    def crash_log(self) -> bytes:
        """Combined output used for crash-signature extraction."""
        return self.stderr + b"\n" + self.stdout


def _harness_env(build_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["OUT"] = str(build_dir)
    env["TESTCASE"] = env.get("TESTCASE", "")
    env.setdefault("ASAN_OPTIONS", DEFAULT_ASAN_OPTIONS)
    env.setdefault("UBSAN_OPTIONS", DEFAULT_UBSAN_OPTIONS)
    # Help the sanitizer find the symbolizer so frames carry file:line.
    symbolizer = build_dir / "llvm-symbolizer"
    if symbolizer.exists():
        env.setdefault("ASAN_SYMBOLIZER_PATH", str(symbolizer))
    env["PATH"] = f"{build_dir}:{env.get('PATH', '')}"
    return env


def resolve_harness(build_dir: Path, harness: str) -> str | None:
    """Resolve a logical harness name to an actual binary in ``build_dir``.

    Handles the ``@OPTION`` / case normalization oss-fuzz performs (mirrors the
    given_fuzzer entrypoint). Returns the binary filename, or None if not found.
    """
    if (build_dir / harness).is_file():
        return harness
    if (build_dir / f"{harness}_fuzzer").is_file():
        return f"{harness}_fuzzer"
    target = harness.lower()
    for path in sorted(build_dir.glob("*")):
        if not path.is_file():
            continue
        normalized = path.name.replace("@", "_").lower()
        if normalized == target:
            return path.name
    return None


def list_harnesses(build_dir: Path) -> list[str]:
    """Discover candidate harness binaries in ``build_dir``.

    Used only when no specific harness is assigned. Returns executables that are
    not known oss-fuzz helpers and not obvious data files.
    """
    found: list[str] = []
    if not build_dir.is_dir():
        return found
    for path in sorted(build_dir.iterdir()):
        if not path.is_file():
            continue
        name = path.name
        if name in _NON_HARNESS_NAMES or name.startswith("."):
            continue
        if name.endswith((".jar", ".zip", ".options", ".txt", ".json", ".yaml", ".so", ".a", ".dict")):
            continue
        if not os.access(path, os.X_OK):
            continue
        found.append(name)
    return found


def run_input(
    build_dir: Path,
    harness: str,
    input_path: Path,
    timeout: int,
) -> RunResult:
    """Execute ``harness`` once on ``input_path`` (libFuzzer/Jazzer reproduce).

    A single positional input argument makes libFuzzer/Jazzer run the one input
    and exit (0 = no crash, non-zero = crash). The process is run in its own
    session so a wall-clock timeout can reap the whole tree.
    """
    binary = build_dir / harness
    if not binary.exists():
        resolved = resolve_harness(build_dir, harness)
        if resolved is None:
            return RunResult(
                127, b"", f"harness not found: {harness}".encode(), False, launch_failed=True
            )
        binary = build_dir / resolved
    if not os.access(binary, os.X_OK):
        try:
            binary.chmod(0o755)
        except OSError:
            pass

    env = _harness_env(build_dir)
    env["TESTCASE"] = str(input_path)
    cmd = [str(binary), str(input_path)]

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(build_dir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as e:
        return RunResult(127, b"", str(e).encode(), False, launch_failed=True)

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return RunResult(proc.returncode, stdout or b"", stderr or b"", False)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        stdout, stderr = b"", b""
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        return RunResult(124, stdout or b"", stderr or b"", True)


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

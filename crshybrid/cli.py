"""Command-line helpers.

``crs-verify`` runs a single input against a harness using the *same* code path
the orchestrator uses to verify candidates, and prints whether it crashed plus
the stack-based dedup signature. Claude uses it to self-check candidates before
saving them.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import dedup
from .config import Config
from .harness import run_input


def verify_main(argv: list[str] | None = None) -> int:
    cfg = Config()
    parser = argparse.ArgumentParser(
        prog="crs-verify",
        description="Run an input against a harness and report whether it crashes.",
    )
    parser.add_argument("input", type=Path, help="Path to the candidate input file")
    parser.add_argument(
        "--harness",
        default=cfg.harness,
        help="Harness name (defaults to OSS_CRS_TARGET_HARNESS)",
    )
    parser.add_argument("--build-dir", type=Path, default=cfg.build_dir)
    parser.add_argument("--timeout", type=int, default=cfg.verify_timeout)
    args = parser.parse_args(argv)

    if not args.harness:
        parser.error("no harness specified and OSS_CRS_TARGET_HARNESS is unset")
    if not args.input.is_file():
        parser.error(f"input file not found: {args.input}")

    result = run_input(args.build_dir, args.harness, args.input, timeout=args.timeout)
    if result.launch_failed:
        print(f"retcode: {result.exit_code}")
        print("crashed: false")
        print("error: harness launch failed")
        sys.stderr.write(result.stderr.decode("utf-8", errors="replace") + "\n")
        return 2

    crashed = result.exit_code != 0 and not result.timed_out
    if result.timed_out:
        crashed = cfg.allow_timeout_bug

    signature = dedup.crash_signature(result.crash_log)
    key = dedup.dedup_key(signature)

    print(f"retcode: {result.exit_code}")
    print(f"timed_out: {str(result.timed_out).lower()}")
    print(f"crashed: {str(crashed).lower()}")
    print(f"dedup_key: {key}")
    print("signature:")
    sys.stdout.write(signature.decode("utf-8", errors="replace") + "\n")
    # Exit code mirrors the orchestrator's verdict (and the 'crashed:' line):
    # 0 = not a submittable crash, non-zero = crash. A hang with
    # HYBRID_ALLOW_TIMEOUT_BUG=0 is NOT a crash, so it exits 0.
    if not crashed:
        return 0
    return result.exit_code or 1


if __name__ == "__main__":
    raise SystemExit(verify_main())

"""Verify → deduplicate → submit loop.

This is the orchestrator's gatekeeper. Both producers — the fuzzer and the Claude
agent — drop *candidate* crashing inputs into watched directories. For every new
candidate the loop:

1. runs it against the harness binary to confirm it actually crashes,
2. extracts a stack-based crash signature (:mod:`crshybrid.dedup`, ported from
   CRS-multilang ``executor.rs``),
3. deduplicates by ``(harness, signature)``,

and only the first input for each unique signature is copied into the libCRS POV
submit directory, where the libCRS daemon auto-submits it. Duplicates and
non-reproducing candidates are dropped.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import dedup
from .config import Config
from .harness import run_input

logger = logging.getLogger("crshybrid.submitter")

# libFuzzer crash-artifact filename prefixes.
_ARTIFACT_PREFIXES = ("crash-", "oom-", "timeout-", "leak-")


def _atomic_write(dst: Path, data: bytes) -> None:
    """Write ``data`` to ``dst`` atomically (temp file + os.replace).

    Prevents a partially written POV from being observed/submitted if the
    process is killed mid-write during shutdown. The temp uses a leading dot so
    the libCRS submit watcher (which skips dotfiles) never enqueues it.
    """
    tmp = dst.with_name("." + dst.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, dst)


def _md5(path: Path) -> str | None:
    import hashlib

    h = hashlib.md5()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


@dataclass
class Stats:
    candidates: int = 0
    verified_crashes: int = 0
    duplicates: int = 0
    non_repro: int = 0
    submitted: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def as_dict(self) -> dict[str, int]:
        return {
            "candidates": self.candidates,
            "verified_crashes": self.verified_crashes,
            "duplicates": self.duplicates,
            "non_repro": self.non_repro,
            "submitted": self.submitted,
        }


class Submitter:
    def __init__(self, cfg: Config, harnesses: list[str], stop: threading.Event, crs=None):
        self.cfg = cfg
        self.harnesses = harnesses
        self._stop = stop
        self._crs = crs
        self._seen_files: set[str] = set()
        self._seen_files_lock = threading.Lock()
        self._seen_sigs: dict[tuple[str, str], str] = {}
        self._seen_sigs_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="verify")
        self.stats = Stats()
        cfg.pov_dir.mkdir(parents=True, exist_ok=True)
        cfg.dedup_state_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        logger.info("Submitter loop started (harnesses=%s)", self.harnesses)
        last_stats = time.time()
        while not self._stop.is_set():
            try:
                self._scan_once()
            except Exception:  # never let the loop die
                logger.exception("scan iteration failed")
            if time.time() - last_stats > 60:
                logger.info("stats: %s", self.stats.as_dict())
                last_stats = time.time()
            self._stop.wait(self.cfg.poll_interval)
        # Final drain so late artifacts are not lost.
        try:
            self._scan_once()
        except Exception:
            logger.exception("final scan failed")
        self._pool.shutdown(wait=True)
        logger.info("Submitter loop stopped. Final stats: %s", self.stats.as_dict())

    # ------------------------------------------------------------------ #
    def _scan_once(self) -> None:
        for path, harness_hint, source in self._discover():
            content_hash = _md5(path)
            if content_hash is None:
                continue
            dedup_token = f"{source}:{harness_hint or '*'}:{content_hash}"
            with self._seen_files_lock:
                if dedup_token in self._seen_files:
                    continue
                self._seen_files.add(dedup_token)
            with self.stats.lock:
                self.stats.candidates += 1
            self._pool.submit(self._process, path, harness_hint, source)

    def _discover(self):
        """Yield (path, harness_hint, source) for every current candidate file."""
        # Fuzzer crash artifacts (harness known from the directory).
        for harness in self.harnesses:
            adir = self.cfg.fuzzer_artifact_dir(harness)
            if adir.is_dir():
                for path in sorted(adir.iterdir()):
                    if path.is_file() and path.name.startswith(_ARTIFACT_PREFIXES):
                        yield path, harness, "fuzzer"
        # Claude / generic candidates (harness unknown → resolve at verify time).
        cand_root = self.cfg.candidate_dir
        if cand_root.is_dir():
            for path in sorted(cand_root.rglob("*")):
                if path.is_file() and not path.name.startswith("."):
                    source = path.parent.name if path.parent != cand_root else "candidate"
                    yield path, None, source

    # ------------------------------------------------------------------ #
    def _resolve_targets(self, harness_hint: str | None) -> list[str]:
        if harness_hint:
            return [harness_hint]
        if self.cfg.harness:
            return [self.cfg.harness]
        return list(self.harnesses)

    def _process(self, path: Path, harness_hint: str | None, source: str) -> None:
        try:
            self._process_inner(path, harness_hint, source)
        except Exception:
            logger.exception("processing candidate failed: %s", path)

    def _process_inner(self, path: Path, harness_hint: str | None, source: str) -> None:
        for harness in self._resolve_targets(harness_hint):
            result = run_input(
                self.cfg.build_dir, harness, path, timeout=self.cfg.verify_timeout
            )
            if result.launch_failed:
                # Could not execute the harness — a setup error, not a crash.
                logger.warning(
                    "harness launch failed (harness=%s candidate=%s): %s",
                    harness, path.name, result.stderr.decode("utf-8", "replace")[:200],
                )
                continue
            crashed = result.exit_code != 0 and not result.timed_out
            if result.timed_out:
                crashed = self.cfg.allow_timeout_bug
            if not crashed:
                continue

            with self.stats.lock:
                self.stats.verified_crashes += 1

            signature = dedup.crash_signature(result.crash_log)
            key = dedup.dedup_key(signature)
            dedup_id = (harness, key)

            with self._seen_sigs_lock:
                if dedup_id in self._seen_sigs:
                    with self.stats.lock:
                        self.stats.duplicates += 1
                    logger.info(
                        "duplicate crash dropped (harness=%s source=%s key=%s) from %s",
                        harness, source, key[:12], path.name,
                    )
                    return
                self._seen_sigs[dedup_id] = path.name

            self._submit(path, harness, source, signature, key)
            return  # one harness crash is enough for this candidate

        with self.stats.lock:
            self.stats.non_repro += 1
        logger.debug("candidate did not reproduce: %s (source=%s)", path.name, source)

    def _submit(self, path: Path, harness: str, source: str, signature: bytes, key: str) -> None:
        pov_name = f"{source}_{harness}_{key[:12]}{path.suffix or '.bin'}"
        pov_path = self.cfg.pov_dir / pov_name
        try:
            data = path.read_bytes()
        except OSError as e:
            logger.warning("could not read candidate %s: %s", path, e)
            return
        if not data:
            logger.debug("skipping zero-byte candidate %s", path.name)
            return
        if not pov_path.exists():
            _atomic_write(pov_path, data)
        # Persist the dedup signature for inspection.
        try:
            (self.cfg.dedup_state_dir / f"{key}.sig").write_bytes(signature)
        except OSError:
            pass
        # Submit synchronously so submission never depends on the batched
        # register_submit_dir watcher flushing before shutdown. libCRS dedups by
        # content hash, so this and the watcher cannot double-submit.
        if self._crs is not None:
            try:
                from libCRS.base import DataType

                self._crs.submit(DataType.POV, pov_path)
            except Exception:
                logger.exception("explicit libCRS submit failed for %s", pov_path)

        with self.stats.lock:
            self.stats.submitted += 1
        empty = " (empty-stack signature)" if dedup.is_empty_signature(signature) else ""
        logger.info(
            "NEW unique bug submitted: pov=%s harness=%s source=%s key=%s%s",
            pov_name, harness, source, key[:12], empty,
        )

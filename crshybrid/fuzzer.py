"""Continuous fuzzing of one or more harnesses via the prebuilt libFuzzer/Jazzer
binaries.

Each harness gets a dedicated worker thread running the harness binary in
libFuzzer fork mode (``-fork=1 -ignore_crashes=1``) so fuzzing keeps going past
crashes and accumulates *every* distinct crash under an artifact directory. The
worker restarts the binary if it exits unexpectedly. Crash artifacts are picked
up, verified, deduplicated and submitted by :mod:`crshybrid.submitter`.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
import zipfile
from pathlib import Path

from .config import Config

logger = logging.getLogger("crshybrid.fuzzer")

_RESTART_BACKOFF = 5  # seconds between worker restarts


class FuzzerManager:
    def __init__(self, cfg: Config, harnesses: list[str]):
        self.cfg = cfg
        self.harnesses = harnesses
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._procs: dict[str, subprocess.Popen] = {}
        self._procs_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        for harness in self.harnesses:
            t = threading.Thread(
                target=self._worker, args=(harness,), name=f"fuzz-{harness}", daemon=True
            )
            t.start()
            self._threads.append(t)
        logger.info("Fuzzer started for harnesses: %s", self.harnesses)

    def stop(self) -> None:
        self._stop.set()
        with self._procs_lock:
            procs = list(self._procs.values())
        for proc in procs:
            _terminate(proc)
        for t in self._threads:
            t.join(timeout=10)

    # ------------------------------------------------------------------ #
    def _seed_corpus(self, harness: str) -> Path:
        corpus = self.cfg.fuzzer_corpus_dir(harness)
        corpus.mkdir(parents=True, exist_ok=True)

        # Bootstrap from fetched seeds.
        if self.cfg.seed_dir.is_dir():
            for seed in self.cfg.seed_dir.rglob("*"):
                if seed.is_file() and not seed.name.startswith("."):
                    dest = corpus / f"seed_{seed.name}"
                    if not dest.exists():
                        try:
                            dest.write_bytes(seed.read_bytes())
                        except OSError:
                            pass

        # Bootstrap from the oss-fuzz bundled seed corpus, if present.
        for cand in (
            self.cfg.build_dir / f"{harness}_seed_corpus.zip",
            self.cfg.build_dir / f"{harness}.zip",
        ):
            if cand.is_file():
                try:
                    with zipfile.ZipFile(cand) as zf:
                        zf.extractall(corpus)
                    logger.info("Seeded %s corpus from %s", harness, cand.name)
                except (zipfile.BadZipFile, OSError) as e:
                    logger.warning("Failed to unzip %s: %s", cand, e)

        # libFuzzer needs at least one input file to start cleanly.
        if not any(p.is_file() for p in corpus.iterdir()):
            (corpus / "seed_empty").write_bytes(b"\n")
        return corpus

    def _build_cmd(self, harness: str, corpus: Path, artifacts: Path) -> list[str]:
        binary = self.cfg.build_dir / harness
        artifacts.mkdir(parents=True, exist_ok=True)
        # artifact_prefix must end with '/' so crashes land *inside* the dir.
        cmd = [
            str(binary),
            f"-artifact_prefix={artifacts}/",
            "-fork=1",
            "-ignore_crashes=1",
            "-ignore_ooms=1",
            "-ignore_timeouts=1",
            f"-rss_limit_mb={self.cfg.fuzzer_rss_mb}",
            f"-timeout={self.cfg.fuzzer_exec_timeout}",
            str(corpus),
        ]
        return cmd

    def _worker(self, harness: str) -> None:
        binary = self.cfg.build_dir / harness
        if not binary.exists():
            logger.error("Harness binary missing, fuzzer worker exiting: %s", binary)
            return
        if not os.access(binary, os.X_OK):
            try:
                binary.chmod(0o755)
            except OSError:
                pass

        corpus = self._seed_corpus(harness)
        artifacts = self.cfg.fuzzer_artifact_dir(harness)
        artifacts.mkdir(parents=True, exist_ok=True)
        work = self.cfg.fuzzer_dir / harness / "work"
        work.mkdir(parents=True, exist_ok=True)
        log_path = self.cfg.fuzzer_dir / harness / "fuzz.log"

        env = os.environ.copy()
        env["OUT"] = str(self.cfg.build_dir)
        env.setdefault(
            "ASAN_OPTIONS",
            "abort_on_error=1:symbolize=1:detect_leaks=0:handle_abort=1:"
            "handle_segv=1:allocator_may_return_null=1:dedup_token_length=3",
        )
        env["PATH"] = f"{self.cfg.build_dir}:{env.get('PATH', '')}"

        cmd = self._build_cmd(harness, corpus, artifacts)
        logger.info("Fuzz cmd for %s: %s", harness, " ".join(cmd))

        while not self._stop.is_set():
            try:
                with open(log_path, "ab") as log_f:
                    log_f.write(f"\n=== fuzz start {time.time()} ===\n".encode())
                    log_f.flush()
                    proc = subprocess.Popen(
                        cmd,
                        cwd=str(work),
                        env=env,
                        stdout=log_f,
                        stderr=log_f,
                        start_new_session=True,
                    )
            except OSError as e:
                logger.error("Failed to launch fuzzer for %s: %s", harness, e)
                break

            with self._procs_lock:
                self._procs[harness] = proc
            ret = proc.wait()
            with self._procs_lock:
                self._procs.pop(harness, None)

            if self._stop.is_set():
                break
            logger.warning(
                "Fuzzer for %s exited (rc=%s); restarting in %ds", harness, ret, _RESTART_BACKOFF
            )
            self._stop.wait(_RESTART_BACKOFF)

        logger.info("Fuzzer worker stopped: %s", harness)


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

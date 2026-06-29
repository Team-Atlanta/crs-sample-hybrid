"""Bidirectional seed sharing between the fuzzer and the Claude agent.

The whole point of the hybrid is division of labor: the agent reasons its way
into hard-to-reach code, and the fuzzer mutates at high throughput around what
the agent (and the fuzzer itself) has found. Seed sharing is what couples them.

Two channels, both deduplicated by content hash:

* **agent → fuzzer** — the coverage seeds the agent writes to ``agent_seed_dir``
  are copied into each target harness's libFuzzer corpus directory. libFuzzer
  fork mode re-reads the corpus between jobs, so externally added files get
  picked up and mutated. Crash candidates are not shared, and — because the
  agent may also drop crashing inputs into the seed dir — every seed is screened
  against the harness first and any that crashes is excluded: a crashing input
  kills the fork child during corpus load and yields nothing to mutate. A
  crashing seed is not discarded, though — it is forwarded to the submitter so
  the bug is still verified, deduplicated and submitted.
* **fuzzer → agent** — a rolling window of the *newest* ``seed_share_max_to_agent``
  corpus inputs is surfaced into a per-harness directory the agent reads, so the
  agent keeps seeing real, harness-accepted inputs (and which structures reach
  deep code) throughout the run, not just an early snapshot.

Files are written atomically (temp + ``os.replace``) so a reader never observes
a partial input. Content hashing makes the two channels loop-safe: an input the
agent re-saves from the shared corpus already exists (same hash) and is skipped.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .harness import run_input

logger = logging.getLogger("crshybrid.seedshare")

# Files in the corpus that we pushed there ourselves — never echoed back to the agent.
_SHARED_PREFIX = "shared_"
# Prefix for inputs surfaced into the agent's view directory.
_VIEW_PREFIX = "fuzz_"


def _md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _md5_file(path: Path) -> str | None:
    h = hashlib.md5()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _atomic_copy(data: bytes, dst: Path) -> None:
    """Write ``data`` to ``dst`` atomically via a hidden temp + ``os.replace``.

    The temp name is a dotfile so a concurrent libFuzzer corpus rescan never even
    considers the partial file.
    """
    tmp = dst.with_name("." + dst.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, dst)


@dataclass
class SeedShareStats:
    to_fuzzer: int = 0
    to_agent: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def as_dict(self) -> dict[str, int]:
        return {"to_fuzzer": self.to_fuzzer, "to_agent": self.to_agent}


class SeedSharer:
    """Periodically syncs seeds between the agent and the fuzzer (see module doc).

    Runs as a single daemon thread, so its in-memory state (the pushed-hash set
    and the corpus-hash cache) needs no locking.
    """

    def __init__(
        self,
        cfg: Config,
        harnesses: list[str],
        stop: threading.Event,
        agent_harness: str | None = None,
    ):
        self.cfg = cfg
        self.harnesses = harnesses
        self._stop = stop
        # Agent seeds are pushed into the corpus of the harness the agent targets
        # (irrelevant seeds just don't add coverage, but pushing to all harnesses
        # would waste fuzzing budget). Fall back to all harnesses if unknown.
        if agent_harness and agent_harness in harnesses:
            self._push_targets = [agent_harness]
        else:
            self._push_targets = list(harnesses)
        # Harness used to screen agent seeds for crashes before they enter the corpus.
        self._verify_harness = self._push_targets[0] if self._push_targets else None
        self._pushed: set[str] = set()  # content hashes already handled agent → fuzzer
        # Cache corpus-file content hashes keyed by name → (mtime, size, hash) so a
        # large corpus is not re-hashed in full every tick. Corpus filenames are
        # content-addressed, so (name, mtime, size) identifies the bytes.
        self._hash_cache: dict[str, tuple[float, int, str]] = {}
        self.stats = SeedShareStats()

    # ------------------------------------------------------------------ #
    def start_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="seedshare", daemon=True)
        t.start()
        return t

    def run(self) -> None:
        logger.info(
            "Seed sharing started (agent→fuzzer targets=%s, fuzzer→agent harnesses=%s, cap=%d)",
            self._push_targets, self.harnesses, self.cfg.seed_share_max_to_agent,
        )
        last_stats = time.time()
        while not self._stop.is_set():
            try:
                self._agent_to_fuzzer()
                self._fuzzer_to_agent()
            except Exception:  # never let the loop die
                logger.exception("seed share iteration failed")
            if time.time() - last_stats > 60:
                logger.info("seed-share stats: %s", self.stats.as_dict())
                last_stats = time.time()
            self._stop.wait(self.cfg.seed_share_interval)
        # Final drain so the last finds on both sides are shared.
        try:
            self._agent_to_fuzzer()
            self._fuzzer_to_agent()
        except Exception:
            logger.exception("final seed share failed")
        logger.info("Seed sharing stopped. Final stats: %s", self.stats.as_dict())

    # ------------------------------------------------------------------ #
    def _cached_hash(self, path: Path) -> str | None:
        """Content hash of a corpus file, memoized by (name, mtime, size)."""
        try:
            st = path.stat()
        except OSError:
            return None
        cached = self._hash_cache.get(path.name)
        if cached is not None and cached[0] == st.st_mtime and cached[1] == st.st_size:
            return cached[2]
        h = _md5_file(path)
        if h is not None:
            self._hash_cache[path.name] = (st.st_mtime, st.st_size, h)
        return h

    # ------------------------------------------------------------------ #
    def _agent_seed_files(self):
        """Yield the coverage seeds the agent has written (not its crash candidates)."""
        root = self.cfg.agent_seed_dir
        if not root.is_dir():
            return
        for p in sorted(root.rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                yield p

    def _is_crashing_seed(self, path: Path) -> bool:
        """True if a seed crashes the harness — such inputs don't belong in the corpus.

        The agent's job is to find crashes, and it may drop those same crashing
        inputs into the seed directory. A crashing seed kills the libFuzzer fork
        child on load and yields nothing to mutate, so we screen them out by
        content (not just by directory) before pushing to the corpus.
        """
        if not self._verify_harness:
            return False
        result = run_input(
            self.cfg.build_dir, self._verify_harness, path, timeout=self.cfg.verify_timeout
        )
        if result.launch_failed:
            return False  # can't screen (harness unavailable); don't drop the seed
        if result.timed_out:
            return self.cfg.allow_timeout_bug
        return result.exit_code != 0

    def _forward_crashing_seed(self, path: Path, h: str, data: bytes) -> bool:
        """Route a crashing seed to the submitter's candidate intake.

        The agent sometimes files a crashing input as a *seed* rather than a
        candidate. We keep it out of the corpus, but a crash is a result — it
        must still be verified, deduplicated and submitted. Dropping a copy into
        the candidate tree (which the submitter scans recursively) reuses the
        existing verify/dedup/submit path; the submitter dedups by crash
        signature, so this never double-submits a crash already filed elsewhere.
        """
        dst_dir = self.cfg.candidate_dir / "from-seed-screen"
        try:
            dst_dir.mkdir(parents=True, exist_ok=True)
            dst = dst_dir / f"crash_{h}{path.suffix or '.bin'}"
            if not dst.exists():
                _atomic_copy(data, dst)
            return True
        except OSError:
            logger.exception("failed to forward crashing seed for submission: %s", path.name)
            return False

    def _agent_to_fuzzer(self) -> None:
        for path in self._agent_seed_files():
            h = _md5_file(path)
            if not h or h in self._pushed:
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if not data:
                continue
            # Exclude crashing inputs from the corpus regardless of which agent
            # directory they came from (the agent may put crashers in the seed dir).
            # A crash must never be silently dropped, so forward it to the
            # submitter instead of just discarding it.
            if self._is_crashing_seed(path):
                self._pushed.add(h)  # screened once; no need to re-verify each tick
                forwarded = self._forward_crashing_seed(path, h, data)
                logger.info(
                    "excluded crashing agent seed from corpus%s: %s",
                    " (forwarded for submission)" if forwarded else "", path.name,
                )
                continue
            all_ok = True
            for harness in self._push_targets:
                corpus = self.cfg.fuzzer_corpus_dir(harness)
                try:
                    corpus.mkdir(parents=True, exist_ok=True)
                    dst = corpus / f"{_SHARED_PREFIX}{h}"
                    if dst.exists():
                        continue
                    _atomic_copy(data, dst)
                    with self.stats.lock:
                        self.stats.to_fuzzer += 1
                    logger.info(
                        "seed shared agent→fuzzer: %s → %s corpus (%s)",
                        path.name, harness, dst.name,
                    )
                except OSError:
                    logger.exception("failed to push seed into corpus for %s", harness)
                    all_ok = False
            # Only mark pushed once every target succeeded, so a transient failure
            # (e.g. one harness) is retried next tick instead of silently dropped.
            if all_ok:
                self._pushed.add(h)

    def _fuzzer_to_agent(self) -> None:
        cap = self.cfg.seed_share_max_to_agent
        for harness in self.harnesses:
            corpus = self.cfg.fuzzer_corpus_dir(harness)
            if not corpus.is_dir():
                continue
            view = self.cfg.fuzzer_seed_view_dir(harness)
            view.mkdir(parents=True, exist_ok=True)

            # Collect non-shared corpus files with their mtimes, skipping any that
            # vanish mid-scan (libFuzzer rewrites/minimizes the corpus). Each file
            # is handled independently — one disappearing file never aborts the tick.
            entries: list[tuple[float, Path]] = []
            try:
                names = list(corpus.iterdir())
            except OSError:
                continue
            for p in names:
                if p.name.startswith(".") or p.name.startswith(_SHARED_PREFIX):
                    continue
                try:
                    st = p.stat()
                except OSError:
                    continue
                if not p.is_file() or st.st_size == 0:
                    continue
                entries.append((st.st_mtime, p))

            # Desired view = the newest `cap` distinct inputs (content-hashed).
            entries.sort(key=lambda t: t[0], reverse=True)
            desired: dict[str, Path] = {}
            for _, p in entries:
                if len(desired) >= cap:
                    break
                h = self._cached_hash(p)
                if h and h not in desired:
                    desired[h] = p

            # Add newly-desired inputs.
            for h, p in desired.items():
                dst = view / f"{_VIEW_PREFIX}{h}"
                if dst.exists():
                    continue
                try:
                    _atomic_copy(p.read_bytes(), dst)
                    with self.stats.lock:
                        self.stats.to_agent += 1
                except OSError:
                    continue

            # Evict view entries that dropped out of the rolling window, so the
            # agent always sees the freshest sample rather than a frozen snapshot.
            try:
                view_files = list(view.iterdir())
            except OSError:
                view_files = []
            for vp in view_files:
                if not vp.name.startswith(_VIEW_PREFIX):
                    continue
                if vp.name[len(_VIEW_PREFIX):] not in desired:
                    try:
                        vp.unlink()
                    except OSError:
                        pass

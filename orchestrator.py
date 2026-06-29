"""crs-sample-hybrid orchestrator.

The single run-phase entrypoint. It runs *both* producers and arbitrates their
output:

* a coverage-guided fuzzer over every in-scope harness (continuous libFuzzer /
  Jazzer), and
* the Claude Code agent, which crafts candidate inputs from source analysis.

Both write candidate crashing inputs into watched directories. A central loop
verifies each candidate against the harness, deduplicates by stack-based crash
signature (ported from CRS-multilang ``executor.rs``), and submits only unique
bugs via libCRS.
"""

from __future__ import annotations

import hashlib
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

from libCRS.base import DataType
from libCRS.cli.main import init_crs_utils

from crshybrid import harness as harness_mod
from crshybrid.config import Config
from crshybrid.fuzzer import FuzzerManager
from crshybrid.seedshare import SeedSharer
from crshybrid.submitter import Submitter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("orchestrator")


def _configure_git() -> None:
    proc = subprocess.run(
        ["git", "config", "--system", "--add", "safe.directory", "*"], capture_output=True
    )
    if proc.returncode != 0:
        subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", "*"], capture_output=True
        )


def _prepare_source(crs, cfg: Config) -> Path:
    """Materialize the (built) source tree and make it a git repo for Claude."""
    try:
        crs.download_build_output("src", cfg.src_dir)
    except Exception as e:
        logger.warning("Failed to download build-output src: %s", e)

    source_dir = cfg.src_dir
    if not source_dir.exists() or not any(source_dir.iterdir()):
        # Fall back to the in-image source (the orchestrator runs FROM the target image).
        fallback = Path("/src")
        if fallback.exists() and any(fallback.iterdir()):
            logger.info("Using in-image source at %s", fallback)
            source_dir = fallback
        else:
            source_dir.mkdir(parents=True, exist_ok=True)

    if not (source_dir / ".git").exists():
        logger.info("Initializing git repo in %s", source_dir)
        subprocess.run(["git", "init"], cwd=source_dir, capture_output=True, timeout=120)
        subprocess.run(["git", "add", "-A"], cwd=source_dir, capture_output=True, timeout=120)
        subprocess.run(
            [
                "git", "-c", "user.name=crs-sample-hybrid",
                "-c", "user.email=crs-sample-hybrid@local",
                "commit", "-m", "initial source",
            ],
            cwd=source_dir, capture_output=True, timeout=180,
        )
    return source_dir


def _stage_ossfuzz_seeds(cfg: Config, harnesses: list[str], cap: int = 2000) -> int:
    """Extract oss-fuzz bundled seed corpora into the shared seed dir.

    For each in-scope harness, unzip ``<harness>_seed_corpus.zip`` (the standard
    oss-fuzz / ClusterFuzz seed corpus shipped in the build output) into
    ``cfg.seed_dir``. These seeds are then used by both producers:
      - the fuzzer's ``_seed_corpus`` bootstraps its libFuzzer corpus from them, and
      - the agent's ``seeds_present`` prompt section points Claude at them
        directly, so it learns the real input format from turn one (instead of
        relying on the seed-share rolling window, which can evict them).
    Files are content-addressed so identical seeds are not duplicated.
    """
    cfg.seed_dir.mkdir(parents=True, exist_ok=True)
    staged = 0
    for harness in harnesses:
        for cand in (
            cfg.build_dir / f"{harness}_seed_corpus.zip",
            cfg.build_dir / f"{harness}.zip",
        ):
            if not cand.is_file():
                continue
            try:
                with zipfile.ZipFile(cand) as zf:
                    for name in zf.namelist():
                        if name.endswith("/") or staged >= cap:
                            continue
                        try:
                            data = zf.read(name)
                        except (zipfile.BadZipFile, OSError):
                            continue
                        if not data:
                            continue
                        dst = cfg.seed_dir / f"ossfuzz_{harness}_{hashlib.md5(data).hexdigest()[:16]}"
                        if not dst.exists():
                            dst.write_bytes(data)
                            staged += 1
                logger.info("Staged oss-fuzz seed corpus: %s", cand.name)
            except (zipfile.BadZipFile, OSError) as e:
                logger.warning("Failed to stage oss-fuzz seeds from %s: %s", cand, e)
    if staged:
        logger.info("Staged %d oss-fuzz seed file(s) into %s (fuzzer + agent will use them)", staged, cfg.seed_dir)
    else:
        logger.info("No oss-fuzz seed corpora found in %s for harnesses %s", cfg.build_dir, harnesses)
    return staged


def _resolve_harnesses(cfg: Config) -> list[str]:
    if cfg.harness:
        actual = harness_mod.resolve_harness(cfg.build_dir, cfg.harness)
        if actual:
            return [actual]
        logger.warning(
            "Assigned harness %r not found in %s; discovering all harnesses",
            cfg.harness, cfg.build_dir,
        )
    discovered = harness_mod.list_harnesses(cfg.build_dir)
    logger.info("Discovered harnesses: %s", discovered)
    return discovered


def _register_log_dir(crs, path: Path) -> None:
    try:
        if path.exists() or path.is_symlink():
            return
        crs.register_log_dir(path)
        logger.info("Registered log dir: %s", path)
    except Exception as e:
        logger.warning("Failed to register log dir %s: %s", path, e)
        path.mkdir(parents=True, exist_ok=True)


def main() -> None:
    cfg = Config()
    logger.info(
        "Starting hybrid orchestrator: target=%s harness=%s language=%s sanitizer=%s",
        cfg.target, cfg.harness, cfg.language, cfg.sanitizer,
    )
    _configure_git()

    crs = init_crs_utils()

    # --- Fetch boot-time inputs (best effort) ----------------------------- #
    for data_type, dst in (
        (DataType.DIFF, cfg.diff_dir),
        (DataType.SEED, cfg.seed_dir),
        (DataType.BUG_CANDIDATE, cfg.bug_candidate_dir),
    ):
        try:
            fetched = crs.fetch(data_type, dst)
            if fetched:
                logger.info("Fetched %d %s file(s) into %s", len(fetched), data_type, dst)
        except Exception as e:
            logger.warning("Fetch %s failed: %s", data_type, e)

    # --- Download build output (harness binaries) ------------------------- #
    cfg.build_dir.mkdir(parents=True, exist_ok=True)
    try:
        crs.download_build_output("build", cfg.build_dir)
        logger.info("Downloaded build output to %s", cfg.build_dir)
    except Exception as e:
        logger.error("Failed to download build output: %s", e)
        sys.exit(1)

    harnesses = _resolve_harnesses(cfg)
    if not harnesses:
        logger.error("No harnesses found in %s — nothing to run", cfg.build_dir)
        sys.exit(1)
    # Harness the agent targets (also the one its seeds are shared into).
    primary = cfg.harness if cfg.harness in harnesses else harnesses[0]

    # --- Prepare working dirs and submission watcher ---------------------- #
    cfg.pov_dir.mkdir(parents=True, exist_ok=True)
    cfg.candidate_dir.mkdir(parents=True, exist_ok=True)
    for source in ("claude",):
        cfg.candidate_dir_for(source).mkdir(parents=True, exist_ok=True)
    # Seed-sharing dirs (pre-create so the agent can list them from the start).
    cfg.agent_seed_dir.mkdir(parents=True, exist_ok=True)
    for harness in harnesses:
        cfg.fuzzer_seed_view_dir(harness).mkdir(parents=True, exist_ok=True)

    # Stage oss-fuzz bundled seed corpora into the shared seed dir, so BOTH the
    # fuzzer (corpus bootstrap) and the agent (its seeds_present prompt) start
    # from real oss-fuzz seeds — the agent gets them directly, not subject to the
    # seed-share rolling window.
    _stage_ossfuzz_seeds(cfg, harnesses)

    submit_thread = threading.Thread(
        target=crs.register_submit_dir, args=(DataType.POV, cfg.pov_dir), daemon=True
    )
    submit_thread.start()
    logger.info("POV submit watcher started for %s", cfg.pov_dir)

    _register_log_dir(crs, cfg.log_dir)
    _register_log_dir(crs, cfg.agent_work_dir)

    source_dir = _prepare_source(crs, cfg)
    logger.info("Source directory: %s", source_dir)

    # --- Shared shutdown signal ------------------------------------------ #
    stop = threading.Event()

    def _handle_signal(signum, _frame):
        logger.info("Received signal %s — shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # --- Start the verify/dedup/submit loop ------------------------------ #
    submitter = Submitter(cfg, harnesses, stop, crs=crs)
    submitter_thread = threading.Thread(target=submitter.run, name="submitter", daemon=True)
    submitter_thread.start()

    # --- Start the fuzzer (always — this is a hybrid CRS) ----------------- #
    fuzzer = FuzzerManager(cfg, harnesses)
    fuzzer.start()

    # --- Start Claude (always — this is a hybrid CRS) --------------------- #
    # The agent is mandatory; it can only be skipped if it has no credentials,
    # which is a misconfiguration. In that case keep the fuzzer running rather
    # than waste the whole run, but flag it loudly.
    claude_thread: threading.Thread | None = None
    has_creds = bool(cfg.llm_api_url and cfg.llm_api_key) or bool(
        os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
    )
    if has_creds:
        claude_thread = threading.Thread(
            target=_run_claude, args=(cfg, source_dir, primary, stop),
            name="claude", daemon=True,
        )
        claude_thread.start()
    else:
        logger.error(
            "No LLM credentials (set CLAUDE_CODE_OAUTH_TOKEN or an llm_config) — "
            "the agent cannot run; continuing fuzzer-only (degraded)"
        )

    # --- Start seed sharing (agent ⇄ fuzzer, always on) ------------------- #
    # The whole point of the hybrid. It only has work when the agent is also
    # live, so it starts whenever Claude does.
    seedshare_thread: threading.Thread | None = None
    if claude_thread is not None:
        sharer = SeedSharer(cfg, harnesses, stop, agent_harness=primary)
        seedshare_thread = sharer.start_thread()

    # --- Run until killed ------------------------------------------------- #
    try:
        while not stop.is_set():
            stop.wait(5)
    finally:
        logger.info("Shutting down orchestrator...")
        fuzzer.stop()
        if seedshare_thread is not None:
            seedshare_thread.join(timeout=30)
        # Allow the submitter's final drain to outlast one worst-case verify
        # (verify_timeout + kill grace) so in-flight unique POVs are not abandoned.
        submitter_thread.join(timeout=cfg.verify_timeout + 30)
        if claude_thread is not None:
            claude_thread.join(timeout=30)
        logger.info("Orchestrator stopped. Final stats: %s", submitter.stats.as_dict())


def _run_claude(cfg: Config, source_dir: Path, harness: str, stop: threading.Event) -> None:
    import importlib

    module_name = f"agents.{cfg.crs_agent}"
    try:
        agent = importlib.import_module(module_name)
    except ImportError as e:
        logger.error("Failed to import agent %r: %s", module_name, e)
        if cfg.crs_agent == "claude_code":
            return
        try:
            agent = importlib.import_module("agents.claude_code")
            logger.warning("Falling back to agents.claude_code")
        except ImportError:
            return
    # Seed sharing is always on in the hybrid, so the agent always gets the
    # shared dirs: it reads the fuzzer's corpus sample and writes coverage seeds.
    fuzzer_seed_dir = cfg.fuzzer_seed_view_dir(harness)
    agent_seed_dir = cfg.agent_seed_dir
    try:
        agent.setup(source_dir, {"llm_api_url": cfg.llm_api_url, "llm_api_key": cfg.llm_api_key})
        produced = agent.run(
            source_dir=source_dir,
            build_dir=cfg.build_dir,
            candidate_dir=cfg.candidate_dir_for("claude"),
            diff_dir=cfg.diff_dir,
            seed_dir=cfg.seed_dir,
            bug_candidate_dir=cfg.bug_candidate_dir,
            harness=harness,
            work_dir=cfg.agent_work_dir,
            language=cfg.language,
            sanitizer=cfg.sanitizer,
            stop_event=stop,
            fuzzer_seed_dir=fuzzer_seed_dir,
            agent_seed_dir=agent_seed_dir,
        )
        logger.info("Claude agent finished (produced candidates: %s)", produced)
    except Exception:
        logger.exception("Claude agent crashed")


if __name__ == "__main__":
    main()

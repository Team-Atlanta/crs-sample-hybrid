"""Runtime configuration for the crs-sample-hybrid orchestrator.

Centralizes the environment variables provided by the oss-crs framework and the
filesystem layout shared between the fuzzer, the Claude agent, and the
verify/dedup/submit loop.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _read_key() -> str:
    key_file = os.environ.get("OSS_CRS_LLM_API_KEY_FILE")
    if key_file and Path(key_file).exists():
        return Path(key_file).read_text().strip()
    return os.environ.get("OSS_CRS_LLM_API_KEY", "")


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    # --- Target identity (set by the framework) ---------------------------- #
    target: str = field(default_factory=lambda: os.environ.get("OSS_CRS_TARGET", ""))
    harness: str = field(default_factory=lambda: os.environ.get("OSS_CRS_TARGET_HARNESS", ""))
    language: str = field(default_factory=lambda: os.environ.get("FUZZING_LANGUAGE", "c"))
    sanitizer: str = field(default_factory=lambda: os.environ.get("SANITIZER", "address"))

    # --- LLM access (LiteLLM proxy injected by the framework) -------------- #
    llm_api_url: str = field(default_factory=lambda: os.environ.get("OSS_CRS_LLM_API_URL", ""))
    llm_api_key: str = field(default_factory=_read_key)
    crs_agent: str = field(default_factory=lambda: os.environ.get("CRS_AGENT", "claude_code"))

    # --- Filesystem layout ------------------------------------------------- #
    work_dir: Path = Path("/work")
    # /out is the canonical oss-fuzz output location; harness wrappers (e.g.
    # Jazzer) resolve siblings relative to it, so we materialize build output there.
    build_dir: Path = Path("/out")
    src_dir: Path = Path("/work/src")

    # --- Knobs ------------------------------------------------------------- #
    enable_fuzzer: bool = field(default_factory=lambda: _bool_env("HYBRID_ENABLE_FUZZER", True))
    enable_claude: bool = field(default_factory=lambda: _bool_env("HYBRID_ENABLE_CLAUDE", True))
    # Count hangs (wall-clock timeouts we had to kill) as bugs. Off by default,
    # matching uniafl's `allow_timeout_bug = false`.
    allow_timeout_bug: bool = field(default_factory=lambda: _bool_env("HYBRID_ALLOW_TIMEOUT_BUG", False))
    # libFuzzer per-exec timeout (seconds) used while fuzzing.
    fuzzer_exec_timeout: int = field(default_factory=lambda: _int_env("HYBRID_FUZZER_TIMEOUT", 25))
    fuzzer_rss_mb: int = field(default_factory=lambda: _int_env("HYBRID_FUZZER_RSS_MB", 2560))
    # Wall-clock budget (seconds) for verifying a single candidate against the harness.
    verify_timeout: int = field(default_factory=lambda: _int_env("HYBRID_VERIFY_TIMEOUT", 90))
    # Overall run budget (seconds); 0 = run until killed.
    agent_timeout: int = field(default_factory=lambda: max(0, _int_env("AGENT_TIMEOUT", 0)))
    # Poll cadence (seconds) for the verify/dedup loop scanning candidate dirs.
    poll_interval: int = field(default_factory=lambda: _int_env("HYBRID_POLL_INTERVAL", 3))

    # --- Derived directories (populated in __post_init__) ------------------ #
    pov_dir: Path = field(init=False)
    candidate_dir: Path = field(init=False)
    fuzzer_dir: Path = field(init=False)
    diff_dir: Path = field(init=False)
    seed_dir: Path = field(init=False)
    bug_candidate_dir: Path = field(init=False)
    agent_work_dir: Path = field(init=False)
    log_dir: Path = field(init=False)
    dedup_state_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        w = self.work_dir
        # Final deduplicated POVs land here; libCRS auto-submits them.
        self.pov_dir = w / "povs"
        # Producers (fuzzer crashes + Claude outputs) drop candidate inputs here.
        self.candidate_dir = w / "candidates"
        self.fuzzer_dir = w / "fuzzer"
        self.diff_dir = w / "diffs"
        self.seed_dir = w / "seeds"
        self.bug_candidate_dir = w / "bug-candidates"
        self.agent_work_dir = w / "agent"
        self.log_dir = w / "logs"
        self.dedup_state_dir = w / "dedup"

    @property
    def is_jvm(self) -> bool:
        return self.language.lower() in ("jvm", "java")

    def candidate_dir_for(self, source: str) -> Path:
        """Per-producer candidate sub-directory (e.g. ``fuzzer``/``claude``)."""
        return self.candidate_dir / source

    def fuzzer_corpus_dir(self, harness: str) -> Path:
        return self.fuzzer_dir / harness / "corpus"

    def fuzzer_artifact_dir(self, harness: str) -> Path:
        return self.fuzzer_dir / harness / "artifacts"

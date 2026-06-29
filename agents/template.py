"""Template agent module for the hybrid orchestrator.

Copy this file to create a new producer agent. Implement setup() and run(),
then set CRS_AGENT=<your_module_name>. The agent writes *candidate* crashing
inputs into candidate_dir; the orchestrator verifies, deduplicates, and submits.
"""

from pathlib import Path


def setup(source_dir: Path, config: dict) -> None:
    """One-time agent configuration (API URL/key, model token, etc.)."""
    raise NotImplementedError("Implement setup() for your agent")


def run(
    source_dir: Path,
    build_dir: Path,
    candidate_dir: Path,
    diff_dir: Path,
    seed_dir: Path,
    bug_candidate_dir: Path,
    harness: str,
    work_dir: Path,
    *,
    language: str = "c",
    sanitizer: str = "address",
    stop_event=None,
    fuzzer_seed_dir: Path | None = None,
    agent_seed_dir: Path | None = None,
) -> bool:
    """Run the agent autonomously.

    The agent should:
    1. Analyze source code and available evidence (diffs, seeds, bug-candidates)
    2. Identify potential vulnerabilities reachable through ``harness``
    3. Craft inputs that trigger crashes
    4. Verify each input (e.g. via ``crs-verify --harness <harness> <input>``)
    5. Write verified candidate inputs to ``candidate_dir`` (the orchestrator
       deduplicates and submits)

    Seed sharing (optional, when the orchestrator passes the dirs):
    - ``fuzzer_seed_dir``: read the fuzzer's live corpus sample for format hints.
    - ``agent_seed_dir``: write coverage-expanding seeds for the fuzzer to mutate.

    Should return True if it produced any candidates, and stop promptly when
    ``stop_event`` is set.
    """
    raise NotImplementedError("Implement run() for your agent")

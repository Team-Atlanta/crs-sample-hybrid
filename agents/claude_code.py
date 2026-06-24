"""Claude Code agent for the hybrid orchestrator.

Runs Claude Code CLI in agentic mode to analyze the target and craft crashing
inputs. Unlike a standalone finder, this agent does NOT submit POVs directly:
it writes *candidate* inputs into ``candidate_dir``. The orchestrator then
verifies each candidate against the harness, deduplicates it against fuzzer and
prior Claude findings (stack-based), and submits only unique bugs via libCRS.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

logger = logging.getLogger("agent.claude_code")

try:
    AGENT_TIMEOUT = int(os.environ.get("AGENT_TIMEOUT", "0"))
except ValueError:
    AGENT_TIMEOUT = 0
if AGENT_TIMEOUT < 0:
    AGENT_TIMEOUT = 0

_TEMPLATE_PATH = Path(__file__).with_suffix(".md")
_SECTIONS_DIR = _TEMPLATE_PATH.with_name("sections")
_SKILLS_DIR = _TEMPLATE_PATH.with_name("skills")


def _load_section(name: str) -> str:
    return (_SECTIONS_DIR / name).read_text()


def _load_prompt_templates() -> dict[str, str]:
    return {
        "agents_md": _TEMPLATE_PATH.read_text(),
        "workflow_find": _load_section("workflow_find.md"),
        "diff_present": _load_section("diff_present.md"),
        "diff_absent": _load_section("diff_absent.md"),
        "seeds_present": _load_section("seeds_present.md"),
        "pre_submit": _load_section("pre_submit.md"),
    }


def _md_inline(value: str) -> str:
    ticks = 1
    while "`" * ticks in value:
        ticks += 1
    fence = "`" * ticks
    return f"{fence}{value}{fence}"


def _list_input_files(input_dir: Path, *, non_empty_only: bool = False) -> list[Path]:
    if not input_dir.exists():
        return []
    files = sorted(f for f in input_dir.rglob("*") if f.is_file() and not f.name.startswith("."))
    if not non_empty_only:
        return files
    return [f for f in files if f.read_text(errors="replace").strip()]


def _install_skills(source_dir: Path, harness: str, build_dir: Path, candidate_dir: Path) -> None:
    target_skills = source_dir / ".claude" / "skills"
    if not _SKILLS_DIR.exists():
        logger.warning("Skills directory not found: %s", _SKILLS_DIR)
        return
    for skill_dir in _SKILLS_DIR.iterdir():
        if not skill_dir.is_dir():
            continue
        dest = target_skills / skill_dir.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(skill_dir, dest)
        skill_md = dest / "SKILL.md"
        if skill_md.exists():
            content = skill_md.read_text()
            content = content.replace("{harness}", harness)
            content = content.replace("{source_dir}", str(source_dir))
            content = content.replace("{build_dir}", str(build_dir))
            content = content.replace("{candidate_dir}", str(candidate_dir))
            skill_md.write_text(content)
        logger.info("Installed skill: %s", skill_dir.name)


def setup(source_dir: Path, config: dict) -> None:
    """One-time Claude Code configuration (auth env, .claude.json, gitignore)."""
    try:
        version_result = subprocess.run(
            ["claude", "--version"], capture_output=True, text=True, timeout=10
        )
        logger.info(
            "Claude Code CLI version: %s",
            version_result.stdout.strip() or version_result.stderr.strip(),
        )
    except OSError as error:
        logger.warning("Failed to get Claude Code version: %s", error)

    llm_api_url = config.get("llm_api_url", "")
    llm_api_key = config.get("llm_api_key", "")

    os.environ["IS_SANDBOX"] = "1"

    oauth_token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
    if oauth_token:
        logger.info("CLAUDE_CODE_OAUTH_TOKEN found, using OAuth authentication")
    elif llm_api_url and llm_api_key:
        os.environ["ANTHROPIC_BASE_URL"] = llm_api_url
        os.environ["ANTHROPIC_AUTH_TOKEN"] = llm_api_key
        os.environ["ANTHROPIC_API_KEY"] = ""
        logger.info("Claude Code configured with LiteLLM proxy: %s", llm_api_url)
        logger.info("ANTHROPIC_MODEL: %s", os.environ.get("ANTHROPIC_MODEL", "(default)"))
    else:
        logger.warning("No LLM API URL/key set, Claude Code may not work")

    claude_config = {
        "numStartups": 0,
        "autoUpdaterStatus": "disabled",
        "userID": "-",
        "hasCompletedOnboarding": True,
        "lastOnboardingVersion": "1.0.0",
        "projects": {
            str(source_dir): {
                "hasTrustDialogAccepted": True,
                "hasCompletedProjectOnboarding": True,
            }
        },
    }
    claude_json = Path.home() / ".claude.json"
    claude_json.write_text(json.dumps(claude_config))
    claude_json.chmod(0o600)
    logger.info("Wrote Claude config to %s", claude_json)

    global_gitignore = Path.home() / ".gitignore"
    existing = global_gitignore.read_text(errors="replace") if global_gitignore.exists() else ""
    lines = [line.rstrip("\n") for line in existing.splitlines()]
    if "CLAUDE.md" not in lines:
        lines.append("CLAUDE.md")
    global_gitignore.write_text("\n".join(lines).rstrip("\n") + "\n")
    subprocess.run(
        ["git", "config", "--global", "core.excludesFile", str(global_gitignore)],
        capture_output=True,
    )
    logger.info("Agent setup complete")


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
) -> bool:
    """Launch Claude Code; verified candidate inputs are written to candidate_dir."""
    work_dir.mkdir(parents=True, exist_ok=True)
    candidate_dir.mkdir(parents=True, exist_ok=True)
    try:
        templates = _load_prompt_templates()
    except OSError as e:
        logger.error("Failed to load prompt template(s): %s", e)
        return False

    _install_skills(source_dir, harness, build_dir, candidate_dir)

    diffs = _list_input_files(diff_dir, non_empty_only=True)
    seeds = _list_input_files(seed_dir)
    bug_candidates = _list_input_files(bug_candidate_dir)

    if diffs:
        diff_list = "\n".join(f"- {_md_inline(str(p))}" for p in diffs)
        diff_section = templates["diff_present"].format(diff_list=diff_list)
    else:
        diff_section = templates["diff_absent"]

    seed_section = (
        templates["seeds_present"].format(seed_dir=_md_inline(str(seed_dir))) if seeds else ""
    )

    if bug_candidates:
        bc_list = "\n".join(f"- {_md_inline(str(p))}" for p in bug_candidates)
        bug_candidate_section = (
            "## Bug-Candidate Reports\n\n"
            "Static analysis reports are available:\n\n"
            f"{bc_list}\n\n"
            "Use these to prioritize which code paths to target.\n"
        )
    else:
        bug_candidate_section = ""

    # These sections embed a {harness} token; Python str.format() does not
    # recurse into substituted values, so they must be formatted up front or the
    # literal "{harness}" leaks into the final CLAUDE.md.
    workflow_section = templates["workflow_find"].format(harness=harness)
    pre_submit_section = templates["pre_submit"].format(harness=harness)

    claude_md = templates["agents_md"].format(
        language=language,
        sanitizer=sanitizer,
        source_dir=source_dir,
        build_dir=build_dir,
        work_dir=work_dir,
        harness=harness,
        candidate_dir=candidate_dir,
        workflow_section=workflow_section,
        diff_section=diff_section,
        seed_section=seed_section,
        bug_candidate_section=bug_candidate_section,
        pre_submit_section=pre_submit_section,
    )
    (source_dir / "CLAUDE.md").write_text(claude_md)

    target = os.environ.get("OSS_CRS_TARGET", source_dir.name)

    prompt_lines = [
        f"Find vulnerabilities in project {_md_inline(target)} through harness {_md_inline(harness)}.",
        f"Write candidate crashing inputs to {_md_inline(str(candidate_dir))}.",
        "",
        "Available evidence:",
        f"- Diff files: {len(diffs)}",
        f"- Seed files: {len(seeds)}",
        f"- Bug-candidate files: {len(bug_candidates)}",
    ]
    if diffs:
        prompt_lines.append("- Diff files: " + " ".join(_md_inline(str(p)) for p in diffs))
    if seeds:
        prompt_lines.append(f"- Seed directory: {_md_inline(str(seed_dir))}")
    if bug_candidates:
        prompt_lines.append(
            "- Bug-candidate report files: " + " ".join(_md_inline(str(p)) for p in bug_candidates)
        )
    prompt_lines += [
        "",
        "Read CLAUDE.md for workflow, environment, and submission instructions.",
        "Keep going until killed — find as many distinct vulnerabilities as possible.",
    ]
    prompt = "\n".join(prompt_lines)

    stdout_log = work_dir / "claude_stdout.log"
    stderr_log = work_dir / "claude_stderr.log"
    system_prompt = (
        f"You are an expert security researcher finding {sanitizer} vulnerabilities "
        f"in `{target}` ({language}). Read and follow CLAUDE.md."
    )
    cmd = [
        "claude",
        "-p",
        "--verbose",
        "--dangerously-skip-permissions",
        "--output-format", "stream-json",
        "--append-system-prompt", system_prompt,
    ]

    (work_dir / "agent_prompt.txt").write_text(prompt)
    (work_dir / "agent_system_prompt.txt").write_text(system_prompt)
    (work_dir / "agent_claude_md.md").write_text(claude_md)
    (work_dir / "agent_cmd.txt").write_text(" ".join(cmd) + "\n")
    logger.info("Agent inputs saved to %s", work_dir)

    try:
        with open(stdout_log, "w") as out_f, open(stderr_log, "w") as err_f:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=out_f,
                stderr=err_f,
                text=True,
                cwd=source_dir,
                start_new_session=True,
            )
            proc.stdin.write(prompt)
            proc.stdin.close()
            deadline = time.time() + AGENT_TIMEOUT if AGENT_TIMEOUT else None
            reason = None
            while True:
                try:
                    proc.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    if stop_event is not None and stop_event.is_set():
                        reason = "orchestrator shutdown"
                        break
                    if deadline is not None and time.time() >= deadline:
                        reason = f"timeout ({AGENT_TIMEOUT}s)"
                        break
            if reason is not None:
                logger.warning("Stopping Claude Code: %s; killing process tree", reason)
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    time.sleep(2)
                    if proc.poll() is None:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait()
            else:
                logger.info("Claude Code exit code: %d", proc.returncode)
    except Exception as e:
        logger.error("Error running Claude Code: %s", e)
        return False

    subprocess.run(["chmod", "-R", "og+rX", str(Path.home() / ".claude")], capture_output=True)

    if proc.returncode != 0:
        logger.warning("Claude Code failed (rc=%d), see %s", proc.returncode, stderr_log)

    candidates = [
        f for f in candidate_dir.rglob("*") if f.is_file() and not f.name.startswith(".")
    ]
    if candidates:
        logger.info("Agent produced %d candidate input(s)", len(candidates))
        return True
    logger.info("Agent did not produce any candidate inputs")
    return False

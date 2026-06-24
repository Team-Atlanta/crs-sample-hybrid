# crs-sample-hybrid

A hybrid bug-finding CRS for the [oss-crs](https://github.com/Team-Atlanta) framework that
combines a **coverage-guided fuzzer** with the **Claude Code agent** behind a single
orchestrator, and submits only **deduplicated** crashes using stack-based deduplication.

## How it works

```
                    ┌──────────────────────── orchestrator ────────────────────────┐
                    │                                                               │
  harness binaries  │   ┌───────────┐  crash artifacts ─┐                          │
  (from build) ─────┼─▶ │  fuzzer   │ ──────────────────┤                          │
                    │   │ (libFuzzer│                    ▼                          │
                    │   │ / Jazzer) │           ┌─────────────────┐   unique POVs   │
                    │   └───────────┘           │ verify → dedup  │ ─────────────▶  │ libCRS
                    │   ┌───────────┐ candidates│  → submit loop  │   (submit dir)  │ auto-submit
  source + diff ────┼─▶ │  Claude   │ ──────────▶                 │                 │
                    │   │  Code     │           └─────────────────┘                 │
                    │   └───────────┘                                               │
                    └───────────────────────────────────────────────────────────────┘
```

The orchestrator (run-phase entrypoint, `orchestrator.py`) runs inside the **target image**,
so it has the full target runtime and can execute the compiled harnesses directly. It:

1. **Runs the fuzzer** (`crshybrid/fuzzer.py`) over every in-scope harness — continuous
   libFuzzer/Jazzer in fork mode (`-fork=1 -ignore_crashes=1`) so it keeps finding *distinct*
   crashes and saves every crash artifact.
2. **Runs Claude Code** (`agents/claude_code.py`) to analyze the source and craft candidate
   crashing inputs. Claude writes **candidates** (it never submits directly); it self-checks
   them with `crs-verify`.
3. **Verifies, deduplicates, and submits** (`crshybrid/submitter.py`): every candidate — from
   the fuzzer *or* Claude — is run against the harness to confirm a crash, reduced to a
   stack-based crash **signature**, and deduplicated. Only the first input for each unique
   signature is copied into the libCRS POV submit directory (auto-submitted by the libCRS daemon).

Whether a crashing input comes from the fuzzer or from Claude, it goes through the **same**
verify → dedup → submit path, so the orchestrator never submits two inputs for the same bug.

## Stack-based deduplication

The deduplication logic in `crshybrid/dedup.py` is a faithful Python port of the crash-log
parsing in CRS-multilang `uniafl/src/executor/executor.rs`:

- **libFuzzer / ASAN (C/C++/Rust/Go)** — `parse_libfuzzer_crash_log`: the call stack from the
  first `#0` frame up to `LLVMFuzzerTestOneInput`, keeping only frames with a valid source path
  (excluding `/src/llvm-project`) and renumbering them.
- **Jazzer (JVM)** — `parse_jazzer_crash_log` / `parse_jazzer_timeout_log`: the Java exception
  / main-thread stack, with addresses filtered out.

`crash_signature()` mirrors `Executor::run_pov` (libFuzzer → Jazzer → Jazzer-timeout → empty
fallback). On top of the faithful port, `dedup_key()` strips nondeterministic hex load
addresses and normalizes whitespace before hashing, so the same call stack deduplicates
regardless of ASLR. Crashes are keyed by `(harness, signature)`.

## Layout

| Path | Purpose |
|------|---------|
| `orchestrator.py` | Run-phase entrypoint (`run_orchestrator`) |
| `crshybrid/dedup.py` | Stack-based crash dedup (port of `executor.rs`) |
| `crshybrid/harness.py` | Run a single input against a harness binary |
| `crshybrid/fuzzer.py` | Continuous libFuzzer/Jazzer fuzzing manager |
| `crshybrid/submitter.py` | Verify → dedup → submit loop |
| `crshybrid/cli.py` | `crs-verify` helper (shared verification path) |
| `agents/claude_code.py` + `agents/claude_code.md` | Claude Code producer agent |
| `bin/compile_target` | Build phase: `compile` + submit `build`/`src` |
| `oss-crs/` | `crs.yaml`, builder + orchestrator Dockerfiles, example compose |

## Configuration

Set via `additional_env` in `crs.yaml` or the compose file:

| Variable | Default | Meaning |
|----------|---------|---------|
| `ANTHROPIC_MODEL` | `claude-opus-4-6` | Claude model |
| `HYBRID_ENABLE_FUZZER` | `1` | Run the fuzzer |
| `HYBRID_ENABLE_CLAUDE` | `1` | Run the Claude agent |
| `HYBRID_ALLOW_TIMEOUT_BUG` | `0` | Treat hangs (wall-clock timeouts) as bugs |
| `HYBRID_FUZZER_RSS_MB` | `2560` | libFuzzer RSS limit |
| `HYBRID_FUZZER_TIMEOUT` | `25` | libFuzzer per-exec timeout (s) |
| `HYBRID_VERIFY_TIMEOUT` | `90` | Per-candidate verification budget (s) |
| `AGENT_TIMEOUT` | `0` | Claude budget in seconds (0 = no limit) |

## Build & run

Copy `oss-crs/example-compose.yaml`, set the local path / resources / LLM, then run via the
oss-crs framework (the run image is built `FROM` the target image; no prepare phase).

```bash
oss-crs run --compose path/to/compose.yaml --target <target>
```

## Adding another producer

Implement `setup()` / `run()` per `agents/template.py` (write verified candidates to
`candidate_dir`), set `CRS_AGENT=<module>`, and the orchestrator handles verification, dedup,
and submission.

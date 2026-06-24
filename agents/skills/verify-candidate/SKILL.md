---
name: verify-candidate
description: How to verify a candidate crashing input against the harness before saving it for the orchestrator
---

# Verify Candidate

Confirm an input actually crashes the harness before writing it to the candidate directory.
You are inside the target runtime, so you can run the harness binary directly.

## Preferred: crs-verify

```bash
# 1. Write a candidate input to a file
python3 -c "import sys; sys.stdout.buffer.write(b'AAAA' * 50)" > /tmp/candidate.bin

# 2. Verify it (sets sanitizer options + a timeout, prints the extracted crash stack)
crs-verify --harness {harness} /tmp/candidate.bin

# Output includes:
#   retcode: <n>        non-zero => crash
#   crashed: true|false
#   signature: <stack>  the stack-based signature the orchestrator deduplicates on
```

## Manual reproduction (equivalent)

```bash
"{build_dir}/{harness}" /tmp/candidate.bin
echo "exit: $?"      # non-zero = crash
```

## Crash indicators by language

**C/C++ (ASAN):** non-zero exit + `AddressSanitizer` / `SEGV` / `ABRT` in stderr, with a `#0 … in <func> <file>:<line>` stack.

**JVM (Jazzer):** non-zero exit (often 77) + `== Java Exception:` / `FuzzerSecurityIssue*` with an `\tat …` stack.

## Saving

Only save inputs that crash. Copy the verified input into the candidate directory:

```bash
cp /tmp/candidate.bin {candidate_dir}/descriptive_name.bin
```

The orchestrator re-verifies, deduplicates by crash stack, and submits unique bugs. Two inputs with the same
crash stack count as one bug — once you've saved a crash, look for a *different* root cause instead of
re-saving variants of the same one.

## Notes

- `crs-verify` uses the same verification path as the orchestrator, so a "crashed: true" here means the
  orchestrator will also see a crash.
- Do **not** write to the POV/submit directory — only to the candidate directory. The orchestrator owns submission.

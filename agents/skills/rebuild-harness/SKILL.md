---
name: rebuild-harness
description: Rebuild the harness with source modifications (debug logs / instrumentation) using libCRS apply-patch-build, to understand a hard bug
---

# Rebuild Harness

Rebuild the harness after modifying source code (e.g., adding debug logs, instrumentation, or testing a hypothesis). Uses the builder sidecar to compile inside the target environment. Use this when a bug is hard to understand from source alone — instrument the code, observe, then craft the crashing input.

## When to Use

- Adding `printf`/`fprintf(stderr, ...)` (C/C++) or logging (JVM) to trace execution paths
- Adding assertions to test hypotheses about vulnerable code
- Instrumenting code to understand input parsing / which branch is taken

## Workflow

```bash
# 1. Edit source files in {source_dir} (it is a git repo)

# 2. Generate a patch
cd {source_dir}
git add -A
git diff --cached > /tmp/debug.diff

# 3. Build with the patch applied (builder sidecar)
libCRS apply-patch-build /tmp/debug.diff /tmp/build_001
cat /tmp/build_001/retcode        # 0 = success, non-zero = build failed
# On failure inspect /tmp/build_001/stderr.log and /tmp/build_001/stdout.log

# 4. Get the rebuild ID (only exists if the build succeeded)
REBUILD_ID=$(cat /tmp/build_001/rebuild_id)

# 5. Run a candidate against the instrumented build
libCRS run-pov /tmp/candidate.bin /tmp/run_debug \
  --harness {harness} --rebuild-id $REBUILD_ID
cat /tmp/run_debug/stderr.log     # your debug output / crash trace
cat /tmp/run_debug/retcode
```

## Notes

- Rebuild IDs are content-addressed: same patch → same rebuild ID (cached). Failed builds are not cached — fix and retry.
- Always reset the source after debugging: `cd {source_dir} && git checkout -- .` — otherwise your instrumentation changes the build the final POV is verified against.
- This is for *understanding* a bug. To **save a real POV**, verify it against the unmodified build with `crs-verify --harness {harness} <input>` (fast, in-image) and write it to the candidate directory `{candidate_dir}` — never save against an instrumented rebuild.
- Builds recompile the project and can be slow; review your diff before building.

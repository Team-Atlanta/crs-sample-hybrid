## Workflow

1. **Analyze** — Read source code, diff (if available), and harness to understand the attack surface. Identify functions with potential vulnerabilities.
2. **Craft** — Write candidate inputs that exercise vulnerable code paths. Use knowledge of the input format and parsing logic.
3. **Verify** — Test each candidate with `crs-verify --harness {harness} <input>`. Confirm a non-zero return code and inspect the crash stack.
4. **Save** — Write verified crashing inputs to the candidate directory with descriptive filenames.
5. **Repeat** — Look for more *distinct* vulnerabilities: different code paths, bug classes, and input structures. Avoid re-triggering a crash you already saved (same stack = duplicate).

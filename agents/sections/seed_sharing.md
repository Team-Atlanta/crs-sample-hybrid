## Live Seed Sharing (Fuzzer ⇄ You)

A coverage-guided fuzzer is running on this **same harness at the same time as you**, and you exchange inputs both ways. Use this — it is the whole point of the hybrid.

**Fuzzer → you.** The fuzzer continuously publishes a sample of its evolving corpus (inputs that reached new code) to:

{fuzzer_seed_dir}

Re-list and read files there throughout your run — it grows as the fuzzer makes progress. Use these real, harness-accepted inputs to:
- learn the exact input format (magic bytes, headers, length/offset fields, checksums) without guessing, and
- see which structures already reach deep code, then craft variants that push *further* — toward the guarded/vulnerable paths the fuzzer has not triggered yet.

**You → fuzzer.** Any input you write to:

{agent_seed_dir}

is handed to the fuzzer to mutate. Drop **structurally-valid, coverage-expanding** seeds here — especially inputs that pass hard gates the fuzzer struggles with on its own (correct magic/length/checksum, deep parser state, a specific opcode sequence). You do the reasoning to *reach* a guarded region; the fuzzer does the high-throughput mutation *around* it to trip the bug.

Notes:
- Seeds you share here do **not** need to crash — they are corpus inputs for the fuzzer to mutate. Crashing inputs still go to the candidate directory as usual (the orchestrator submits those).
- Don't just copy the fuzzer's seeds back — contribute inputs that add something (reach new code, satisfy a new constraint).

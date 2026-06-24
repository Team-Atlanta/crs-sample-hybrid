# =============================================================================
# crs-sample-hybrid Orchestrator Dockerfile (RUN phase)
# =============================================================================
# Runs FROM the target image so it has the full target runtime and can execute
# the compiled libFuzzer / Jazzer harnesses directly — both for continuous
# fuzzing and for single-input crash verification (no runner sidecar needed).
# Node + Claude Code CLI + Python + libCRS are layered on top.
# =============================================================================

ARG target_base_image
ARG crs_version

FROM ${target_base_image}

ENV DEBIAN_FRONTEND=noninteractive

# Base tooling. `|| true` keeps the build resilient across the various Ubuntu
# bases oss-fuzz uses; the essentials are re-checked below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git rsync gnupg \
        python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/* || true

# Node.js 20 (required by the Claude Code CLI).
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Claude Code CLI (pinned to avoid breaking .claude.json schema changes).
ARG CLAUDE_CODE_CLI_VERSION=2.1.168
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_CLI_VERSION}

# pwntools for input crafting.
RUN pip3 install --no-cache-dir pwntools \
    || pip3 install --no-cache-dir --break-system-packages pwntools || true

# libCRS (CLI + Python package). Use pip directly (like the reference finder)
# rather than install.sh, whose `apt-get update` under `set -e` would abort the
# build on a flaky/pinned apt source. rsync (installed above) is libCRS's only
# system dependency.
COPY --from=libcrs . /libCRS
RUN pip3 install --no-cache-dir /libCRS \
    || pip3 install --no-cache-dir --break-system-packages /libCRS

# Orchestrator package (orchestrator entrypoint, crshybrid lib, agents).
COPY pyproject.toml /opt/crs-sample-hybrid/pyproject.toml
COPY orchestrator.py /opt/crs-sample-hybrid/orchestrator.py
COPY crshybrid/ /opt/crs-sample-hybrid/crshybrid/
COPY agents/ /opt/crs-sample-hybrid/agents/
RUN pip3 install --no-cache-dir /opt/crs-sample-hybrid \
    || pip3 install --no-cache-dir --break-system-packages /opt/crs-sample-hybrid

# Belt-and-suspenders so `python3 orchestrator.py` also resolves the packages.
ENV PYTHONPATH=/opt/crs-sample-hybrid
WORKDIR /opt/crs-sample-hybrid

# Sanity check.
RUN python3 -c "from libCRS.base import DataType; import crshybrid.dedup; print('crs-sample-hybrid OK')"

CMD ["run_orchestrator"]

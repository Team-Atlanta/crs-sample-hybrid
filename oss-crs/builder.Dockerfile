# =============================================================================
# crs-sample-hybrid Builder Dockerfile
# =============================================================================
# BUILD phase: compiles the target project with the standard oss-fuzz `compile`
# and submits the harness binaries (/out) and source tree (/src).
# =============================================================================

ARG target_base_image
ARG crs_version

FROM ${target_base_image}

# rsync is required by libCRS copy helpers.
RUN apt-get update -qq && apt-get install -y -qq rsync >/dev/null 2>&1 || true

# Install libCRS (CLI + Python package). Use pip directly (like the reference
# finder) rather than install.sh, whose `apt-get update` under `set -e` would
# abort the build on a flaky/pinned apt source. rsync (installed above) is the
# only system dependency libCRS needs.
COPY --from=libcrs . /libCRS
RUN pip3 install --no-cache-dir /libCRS \
    || pip3 install --no-cache-dir --break-system-packages /libCRS
RUN python3 -c "from libCRS.base import DataType; print('libCRS OK')"

COPY bin/compile_target /usr/local/bin/compile_target
RUN chmod +x /usr/local/bin/compile_target

CMD ["compile_target"]

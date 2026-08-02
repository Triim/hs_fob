# GradED — one image for both the live node runner and the static frontend.
#
# Base is the official uv image on Python 3.12, so dependency install matches the
# committed uv.lock exactly (reproducible builds). The same image is reused by
# both docker-compose services; only the command differs.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# libsodium is IPv8's optional native crypto backend; harmless if unused, and it
# keeps the overlay's key handling on a fast path when present.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsodium23 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# uv settings: copy wheels into the venv (no hardlinks across the layer boundary)
# and put the venv at a stable path.
ENV UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

# Install dependencies first, from the lockfile, so this layer caches across code
# changes. --no-install-project: only third-party deps here, not the app itself.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Now the application code. .dockerignore keeps *.pem, .venv, caches, .git out —
# IPv8 keypairs are generated fresh inside the container at first run.
COPY . .

# Bind the HTTP bridges to all interfaces so the host-mapped ports are reachable
# (run_nodes defaults to 127.0.0.1 for local, non-Docker use).
ENV HS_FOB_HTTP_HOST=0.0.0.0 \
    HS_FOB_HTTP_PORT=8080 \
    PYTHONUNBUFFERED=1

# 7 validators: HTTP bridges 8080-8086, IPv8 UDP 9090-9096.
EXPOSE 8080-8086
EXPOSE 8090

# Default command runs the live node cluster; the frontend service overrides it.
CMD ["python", "-m", "network.run_nodes", "--nodes", "7"]

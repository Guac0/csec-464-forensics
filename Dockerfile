# syntax=docker/dockerfile:1
#
# Forensics Tool - single-user PoC image.
# Runs the FastAPI app and the volatility3 CLI (`vol`) as a non-root user.
# Evidence is mounted read-only at /evidence; state lives in /data and /symbols, backups in
# /backups (keep it a separate volume from /data).

ARG PYTHON_IMAGE=python:3.12-slim-trixie
FROM ${PYTHON_IMAGE}

ARG APP_UID=1000
ARG APP_GID=1000

LABEL org.opencontainers.image.title="forensics-tool" \
      org.opencontainers.image.description="PoC: single-user web GUI for AI-assisted volatility3 RAM analysis"
# (version/revision labels are set at the END of this file: VCS_REF changes on every commit, and
# Docker rebuilds every step after the first one that uses a changed build arg. Source/created/
# etc. labels are added by docker/metadata-action in publish.yml.)

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    FT_EVIDENCE_DIR=/evidence \
    FT_DATA_DIR=/data \
    FT_SYMBOLS_DIR=/symbols \
    FT_BACKUP_DIR=/backups

WORKDIR /app

# --- Dependency layer (cached until pyproject.toml changes) -------------------------------
# Install runtime deps + the `volatility` extra + the build backend straight from
# pyproject.toml, without the app source, so editing app/ does not invalidate this layer.
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/pip \
    python - <<'EOF' > /tmp/requirements.txt && pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt
import tomllib
with open("pyproject.toml", "rb") as f:
    data = tomllib.load(f)
reqs = list(data["project"]["dependencies"])
reqs += data["project"]["optional-dependencies"]["volatility"]
reqs += data["build-system"]["requires"]
print("\n".join(reqs))
EOF

# --- Application layer ---------------------------------------------------------------------
COPY app ./app
# Editable install: registers the package (`pip install .[volatility]` equivalent, deps are
# already present) while serving templates/static straight from /app/app.
RUN pip install --no-deps --no-build-isolation -e ".[volatility]"

# volatility3 creates its cache dir at import time and stores automatically downloaded Windows
# symbols (ISF) under $XDG_CACHE_HOME/volatility3. Point it into the persistent, writable
# /symbols volume so downloads survive container restarts. (Set only after the pip installs,
# because pip honours XDG_CACHE_HOME too.)
ENV XDG_CACHE_HOME=/symbols/cache

RUN vol -h > /dev/null \
    && groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid app --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data /symbols/cache /evidence /backups \
    && chown -R app:app /data /symbols /backups \
    && chmod 0755 /evidence

USER app

VOLUME ["/data", "/symbols", "/backups"]
EXPOSE 8000

# No curl in the slim image; use the stdlib. Proxies are bypassed on purpose.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --start-interval=2s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request as u; r = u.build_opener(u.ProxyHandler({})).open('http://127.0.0.1:8000/health', timeout=4); sys.exit(0 if r.status == 200 else 1)"]

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]

# Per-build values last, so a new commit (VCS_REF) or version does not invalidate the cached
# dependency and application layers above.
ARG VERSION=0.1.0-dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

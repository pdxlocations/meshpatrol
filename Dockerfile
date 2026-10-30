FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY meshpatrol/ ./meshpatrol/
RUN pip wheel --wheel-dir /wheels .


FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY --from=builder /wheels /wheels
RUN pip install --no-index --no-deps /wheels/*.whl \
    && rm -rf /wheels \
    && groupadd --gid 10001 meshpatrol \
    && useradd --uid 10001 --gid meshpatrol --no-create-home meshpatrol \
    && mkdir -p /app/meshpatrol-data \
    && chown meshpatrol:meshpatrol /app/meshpatrol-data

WORKDIR /app
USER meshpatrol

EXPOSE 5050/tcp
STOPSIGNAL SIGINT
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/api/snapshot', timeout=4).read()"]

ENTRYPOINT ["python", "-m", "meshpatrol"]

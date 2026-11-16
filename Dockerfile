FROM python:3.12-slim

# 用官方镜像里的 uv，避免在容器里再 pip install 一次
COPY --from=ghcr.io/astral-sh/uv:0.7.14 /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    MIHOMO_HUB_DATA=/data \
    MIHOMO_HUB_HOST=0.0.0.0 \
    MIHOMO_HUB_PORT=8091

WORKDIR /app

# 先只装依赖，代码改动不会让这一层失效
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev

COPY app ./app
COPY run.py ./

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8091

ENV PATH="/app/.venv/bin:$PATH"

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8091/healthz', timeout=3).status==200 else 1)"

CMD ["python", "run.py"]

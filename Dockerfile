FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/sentinelflow

RUN groupadd --system app && useradd --system --gid app --home-dir /nonexistent app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir .

USER app:app

ENTRYPOINT ["sentinelflow"]
CMD ["--help"]

# Typo Sniper - Dockerfile
# Licensed under the GNU AGPL v3. Commercial licensing: see COMMERCIAL.md

FROM python:3.13-slim AS builder

WORKDIR /build

# Build wheels in a throwaway stage so no compiler ends up in the final image
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


FROM python:3.13-slim

LABEL maintainer="chiefgyk3d"
LABEL org.opencontainers.image.title="Typo Sniper"
LABEL org.opencontainers.image.description="Advanced Domain Typosquatting Detection Tool"
LABEL org.opencontainers.image.version="1.1.0"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
LABEL org.opencontainers.image.source="https://github.com/ChiefGyk3D/typo-sniper"

WORKDIR /app

COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

# Copy application files from src directory
COPY src/ .

# Run as an unprivileged user. The scanner only needs outbound network access,
# so there is no reason to give it root inside the container.
RUN useradd --create-home --uid 10001 sniper \
    && mkdir -p /app/data /app/results /home/sniper/.typo_sniper/cache \
    && chown -R sniper:sniper /app /home/sniper

USER sniper

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV CACHE_DIR=/home/sniper/.typo_sniper/cache

VOLUME ["/app/data", "/app/results", "/home/sniper/.typo_sniper/cache"]

ENTRYPOINT ["python", "typo_sniper.py"]
CMD ["--help"]

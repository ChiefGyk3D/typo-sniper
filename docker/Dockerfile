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

# Install the package itself, so the image runs the same console script an
# operator gets from PyPI rather than a loose copy of the modules. --no-deps
# because the pinned requirements are already installed from the wheel stage
# above; this step is only here to place the package and its entry point.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-deps .

# boto3, for the AWS Secrets Manager backend and for shipping reports to S3.
#
# It is in the image rather than left to an extra because the container is how
# people run this on AWS, and there the omission is silent: without boto3 the
# documented AWS secrets backend resolves nothing and the scan runs with no API
# keys at all, reporting no error. Weighing ~90MB against a scanner that
# quietly runs unauthenticated, the megabytes lose.
RUN pip install --no-cache-dir "boto3>=1.35.0"

# Ships scan reports to S3 after a run. Used by the Terraform modules in
# infra/; harmless and inert when RESULTS_BUCKET is unset.
COPY docker/upload-results.py /usr/local/bin/typo-sniper-upload
RUN chmod 0755 /usr/local/bin/typo-sniper-upload

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

ENTRYPOINT ["typo-sniper"]
CMD ["--help"]

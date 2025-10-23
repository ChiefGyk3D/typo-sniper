# Typo Sniper - Dockerfile
# Mozilla Public License 2.0

FROM python:3.14-slim

LABEL maintainer="chiefgyk3d"
LABEL version="1.0.3"
LABEL description="Typo Sniper - Advanced Domain Typosquatting Detection Tool"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir dnspython

# Copy application files from src directory
COPY src/ .

# Create directories for data and results
RUN mkdir -p /app/data /app/results /root/.typo_sniper/cache

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV CACHE_DIR=/root/.typo_sniper/cache

# Volume mounts for persistent data
VOLUME ["/app/data", "/app/results", "/root/.typo_sniper/cache"]

# Default command
ENTRYPOINT ["python", "typo_sniper.py"]
CMD ["--help"]

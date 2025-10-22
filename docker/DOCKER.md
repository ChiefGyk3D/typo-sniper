# Typo Sniper - Docker Guide

This guide explains how to run Typo Sniper in Docker.

## Quick Start

### 1. Build the Docker Image

```bash
# Build from the project root directory
docker build -f docker/Dockerfile -t typo-sniper:1.0.0 .
```

### 2. Run a Basic Scan

```bash
# Using your local domain list (run from project root)
docker run --rm \
  -v "$(pwd)/src/monitored_domains.txt:/app/data/monitored_domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:1.0.0 \
  -i /app/data/monitored_domains.txt \
  -o /app/results \
  --format excel json
```

## Using Docker Compose

### Basic Usage

```bash
# Run from the docker directory
cd docker

# Build and run
docker-compose up

# Run in detached mode
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down

# Return to project root
cd ..
```

### Run Scheduled Scanning

```bash
# Run with the scheduled profile (from docker directory)
cd docker
docker-compose --profile scheduled up -d
cd ..
```

## Common Use Cases

**Note:** Run all commands from the project root directory.

### 1. One-Time Scan

```bash
docker run --rm \
  -v "$(pwd)/src/monitored_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:1.0.0 \
  -i /app/data/domains.txt \
  -o /app/results \
  --format excel json csv html
```

### 2. Scan with Recent Registration Filter

```bash
docker run --rm \
  -v "$(pwd)/src/monitored_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:1.0.0 \
  -i /app/data/domains.txt \
  -o /app/results \
  --months 3 \
  --format excel
```

### 3. Verbose Mode with Cache Disabled

```bash
docker run --rm \
  -v "$(pwd)/src/monitored_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:1.0.0 \
  -i /app/data/domains.txt \
  -o /app/results \
  --no-cache \
  -v \
  --format json
```

### 4. Using Persistent Cache

```bash
# Create a named volume for cache
docker volume create typo-sniper-cache

# Run with persistent cache
docker run --rm \
  -v "$(pwd)/src/monitored_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  -v typo-sniper-cache:/root/.typo_sniper/cache \
  typo-sniper:1.0.0 \
  -i /app/data/domains.txt \
  -o /app/results \
  --format excel json
```

### 5. Performance Tuning

```bash
docker run --rm \
  -v "$(pwd)/src/monitored_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:1.0.0 \
  -i /app/data/domains.txt \
  -o /app/results \
  --max-workers 20 \
  --format excel
```

## Volume Mounts

The Docker container uses the following volume mounts:

- **Input**: `/app/data/` - Mount your domain list here
- **Output**: `/app/results/` - Results are written here
- **Cache**: `/root/.typo_sniper/cache/` - WHOIS cache for faster subsequent scans

## Environment Variables

You can customize behavior with environment variables:

```bash
docker run --rm \
  -e PYTHONUNBUFFERED=1 \
  -e CACHE_DIR=/root/.typo_sniper/cache \
  -v "$(pwd)/monitored_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:1.0.0 \
  -i /app/data/domains.txt
```

## Docker Compose Configuration

### Basic Configuration

The default `docker-compose.yml` configuration:
- Mounts `monitored_domains.txt` as read-only
- Saves results to `./results/`
- Uses persistent cache volume
- Exports to all formats (excel, json, csv, html)

### Custom Configuration

Create a `docker-compose.override.yml`:

```yaml
version: '3.8'

services:
  typo-sniper:
    command: ["-i", "/app/data/monitored_domains.txt", "-o", "/app/results", "--months", "6", "--format", "excel"]
    environment:
      - MAX_WORKERS=15
```

Then run:
```bash
docker-compose up
```

## Scheduled Scanning with Cron

### Using Docker + Host Cron

Add to your crontab:

```bash
# Run every day at 2 AM
0 2 * * * docker run --rm -v /path/to/domains.txt:/app/data/domains.txt:ro -v /path/to/results:/app/results -v typo-sniper-cache:/root/.typo_sniper/cache typo-sniper:1.0.0 -i /app/data/domains.txt -o /app/results --months 1 --format excel json
```

### Using Docker Compose

The `typo-sniper-scheduled` service can be adapted for scheduled runs.

## Building for Different Platforms

### Build for ARM64 (Apple Silicon, Raspberry Pi)

```bash
docker buildx build --platform linux/arm64 -t typo-sniper:1.0.0-arm64 .
```

### Build Multi-Platform

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t typo-sniper:1.0.0 .
```

## Pushing to Docker Registry

### Tag and Push to Docker Hub

```bash
# Tag the image
docker tag typo-sniper:1.0.0 yourusername/typo-sniper:1.0.0
docker tag typo-sniper:1.0.0 yourusername/typo-sniper:latest

# Push to Docker Hub
docker push yourusername/typo-sniper:1.0.0
docker push yourusername/typo-sniper:latest
```

### Using from Docker Hub

```bash
docker pull yourusername/typo-sniper:1.0.0
docker run --rm -v "$(pwd)/domains.txt:/app/data/domains.txt:ro" -v "$(pwd)/results:/app/results" yourusername/typo-sniper:1.0.0 -i /app/data/domains.txt
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Typo Sniper Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker Image
        run: docker build -t typo-sniper:1.0.0 .
      
      - name: Run Scan
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/monitored_domains.txt:/app/data/domains.txt:ro \
            -v ${{ github.workspace }}/results:/app/results \
            typo-sniper:1.0.0 \
            -i /app/data/domains.txt \
            -o /app/results \
            --months 1 \
            --format excel json
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: results/
```

## Kubernetes Deployment

### Basic CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: typo-sniper-scan
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: typo-sniper
            image: typo-sniper:1.0.0
            args:
              - "-i"
              - "/app/data/monitored_domains.txt"
              - "-o"
              - "/app/results"
              - "--months"
              - "1"
              - "--format"
              - "excel"
              - "json"
            volumeMounts:
            - name: domains
              mountPath: /app/data
              readOnly: true
            - name: results
              mountPath: /app/results
            - name: cache
              mountPath: /root/.typo_sniper/cache
          volumes:
          - name: domains
            configMap:
              name: monitored-domains
          - name: results
            persistentVolumeClaim:
              claimName: typo-sniper-results
          - name: cache
            persistentVolumeClaim:
              claimName: typo-sniper-cache
          restartPolicy: OnFailure
```

## Troubleshooting

### Permission Issues

If you encounter permission issues with mounted volumes:

```bash
# Run with user mapping
docker run --rm \
  --user $(id -u):$(id -g) \
  -v "$(pwd)/monitored_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:1.0.0 \
  -i /app/data/domains.txt
```

### Cache Issues

Clear the Docker cache volume:

```bash
docker volume rm typo-sniper-cache
```

### Memory Issues

Increase Docker memory allocation or reduce workers:

```bash
docker run --rm \
  --memory="2g" \
  -v "$(pwd)/domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:1.0.0 \
  -i /app/data/domains.txt \
  --max-workers 5
```

### View Container Logs

```bash
# Using docker run
docker logs <container-id>

# Using docker-compose
docker-compose logs -f typo-sniper
```

## Best Practices

1. **Use named volumes** for cache to persist WHOIS data
2. **Mount domain lists as read-only** to prevent accidental modification
3. **Use specific tags** instead of `:latest` in production
4. **Set resource limits** in production environments
5. **Regular cleanup** of old result files
6. **Monitor disk usage** for results and cache directories

## Example Scripts

### Automated Daily Scan Script

Create `scan.sh`:

```bash
#!/bin/bash

DOMAIN_FILE="monitored_domains.txt"
RESULTS_DIR="./results"
DOCKER_IMAGE="typo-sniper:1.0.0"

# Create results directory if it doesn't exist
mkdir -p "$RESULTS_DIR"

# Run scan
docker run --rm \
  -v "$(pwd)/$DOMAIN_FILE:/app/data/domains.txt:ro" \
  -v "$(pwd)/$RESULTS_DIR:/app/results" \
  -v typo-sniper-cache:/root/.typo_sniper/cache \
  "$DOCKER_IMAGE" \
  -i /app/data/domains.txt \
  -o /app/results \
  --months 1 \
  --format excel json \
  -v

echo "Scan completed. Results saved to $RESULTS_DIR"
```

Make it executable:
```bash
chmod +x scan.sh
./scan.sh
```

## Security Considerations

1. **Network isolation**: Run in a separate Docker network if needed
2. **Read-only filesystem**: Consider making the container filesystem read-only
3. **No privileged mode**: Never run with `--privileged`
4. **Scan images**: Regularly scan the Docker image for vulnerabilities
5. **Minimal base image**: The Dockerfile uses `python:3.10-slim` for smaller attack surface

## Next Steps

- Integrate with your CI/CD pipeline
- Set up automated scheduled scans
- Export results to SIEM or threat intelligence platforms
- Create custom Docker images with pre-configured settings

#!/usr/bin/env bash
# Regenerate the committed sample reports and the README screenshot.
#
# Run this whenever report output changes in any visible way (new columns,
# layout, scoring display) so results/sample.* and media/report.png keep
# showing what the tool actually produces. The README screenshot is a
# function screenshot — it must always match current behaviour.
#
# Requirements: a machine with unrestricted outbound network (DNS, RDAP,
# HTTPS to crt.sh) and a Chromium/Chrome binary for the screenshot.
#
# Usage:
#   scripts/refresh_samples.sh [domain]
#
#   domain: the domain to scan (default: eff.org, matching the existing
#           samples). URLScan enrichment is included when
#           TYPO_SNIPER_URLSCAN_API_KEY is set.

set -euo pipefail

DOMAIN="${1:-eff.org}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

cd "$REPO_ROOT"

echo "==> Scanning ${DOMAIN} with full enrichment"
echo "$DOMAIN" > "$WORKDIR/domains.txt"

cat > "$WORKDIR/config.yaml" <<EOF
enable_certificate_transparency: true
enable_http_probe: true
enable_risk_scoring: true
enable_page_analysis: true
output_dir: $WORKDIR/out
cache_dir: $WORKDIR/cache
EOF

python -m typo_sniper \
    -i "$WORKDIR/domains.txt" \
    --config "$WORKDIR/config.yaml" \
    --format excel json csv html \
    --no-diff

echo "==> Installing fresh samples into results/"
for ext in json csv html xlsx; do
    src=$(ls -t "$WORKDIR"/out/typo_sniper_results_*."$ext" | head -1)
    cp "$src" "results/sample.$ext"
    echo "    results/sample.$ext"
done

echo "==> Rendering media/report.png (1400x953 at 2x scale, top of the HTML report)"
CHROME="${CHROME:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)}"
if [ -z "$CHROME" ]; then
    echo "!! No Chromium/Chrome found; skipping the screenshot." >&2
    echo "   Set CHROME=/path/to/chrome and re-run to regenerate media/report.png" >&2
    exit 1
fi

"$CHROME" --headless=new --no-sandbox --disable-gpu --hide-scrollbars \
    --window-size=1400,953 --force-device-scale-factor=2 \
    --screenshot="media/report.png" \
    "file://$REPO_ROOT/results/sample.html"

echo "==> Done. Review the diff, then commit results/sample.* and media/report.png"

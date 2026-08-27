"""
Scan history and change detection.

A defender running this daily does not want to re-read the same seventy rows
every morning; they want to know what changed. This module persists each scan
and diffs the current one against the previous, so reports and alerts can lead
with new registrations, newly activated sites, and escalating risk instead of
restating the steady state.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import json
import logging
import time
from pathlib import Path
from typing import Any

# Fields whose change is meaningful enough to report. Each entry maps the
# permutation key to the label used in reports and alerts.
TRACKED_FIELDS = {
    'risk_score': 'risk score',
    'created_days_ago': 'registration age',
    'whois_registrar': 'registrar',
    'whois_org': 'organization',
    'whois_registrant': 'registrant',
}

# Change kinds, ordered by how much they warrant attention
NEW = 'new'
ESCALATED = 'escalated'
ACTIVATED = 'activated'
CHANGED = 'changed'
RESOLVED = 'resolved'

SEVERITY_ORDER = [NEW, ESCALATED, ACTIVATED, CHANGED, RESOLVED]


class ScanHistory:
    """Persist scan results and compute deltas between runs."""

    def __init__(self, state_dir: Path, retain: int = 30):
        """
        Args:
            state_dir: Directory holding per-domain history files
            retain: Number of historical scans to keep per domain
        """
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.retain = max(1, retain)
        self.logger = logging.getLogger(__name__)

    def _path_for(self, domain: str) -> Path:
        """Return the history file for a monitored domain."""
        import hashlib

        # The domain is used for the filename; hash it so that unusual
        # characters and length limits cannot produce an invalid path.
        digest = hashlib.sha256(domain.lower().encode()).hexdigest()[:32]
        return self.state_dir / f"{digest}.json"

    def load(self, domain: str) -> list[dict[str, Any]]:
        """
        Load the stored scan history for a domain, newest first.

        Args:
            domain: Monitored domain

        Returns:
            List of stored scan snapshots
        """
        path = self._path_for(domain)
        if not path.exists():
            return []

        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            scans = data.get('scans', [])
            return scans if isinstance(scans, list) else []
        except (OSError, json.JSONDecodeError) as e:
            self.logger.warning(f"Could not read scan history for {domain}: {e}")
            return []

    def record(self, result: dict[str, Any]) -> None:
        """
        Append a scan result to the domain's history.

        Only the fields needed for diffing are stored, so history files stay
        small enough to keep many scans without bloating the state directory.

        Args:
            result: Scan result dictionary from the scanner
        """
        domain = result.get('original_domain')
        if not domain:
            return

        snapshot = {
            'scan_date': result.get('scan_date'),
            'recorded_at': time.time(),
            'registered_count': result.get('registered_count', 0),
            'permutations': {
                p['domain']: self._snapshot_permutation(p)
                for p in result.get('permutations', [])
                if p.get('domain')
            },
        }

        scans = self.load(domain)
        scans.insert(0, snapshot)
        del scans[self.retain:]

        path = self._path_for(domain)
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump({'domain': domain, 'scans': scans}, f, indent=2)
        except OSError as e:
            self.logger.warning(f"Could not write scan history for {domain}: {e}")

    @staticmethod
    def _snapshot_permutation(perm: dict[str, Any]) -> dict[str, Any]:
        """Reduce a permutation to the fields that diffing needs."""
        threat = perm.get('threat_intel') or {}
        http = threat.get('http_probe') or {}
        ct = threat.get('certificate_transparency') or {}
        urlscan = threat.get('urlscan') or {}

        return {
            'fuzzer': perm.get('fuzzer'),
            'risk_score': perm.get('risk_score'),
            'created_days_ago': perm.get('created_days_ago'),
            'is_recent': perm.get('is_recent', False),
            'dns_a': list(perm.get('dns_a') or []),
            'dns_mx': list(perm.get('dns_mx') or []),
            'whois_registrar': perm.get('whois_registrar'),
            'whois_org': perm.get('whois_org'),
            'whois_registrant': perm.get('whois_registrant'),
            'http_active': bool(http.get('http_active')),
            'https_active': bool(http.get('https_active')),
            'tls_verified': http.get('tls_verified'),
            'title': http.get('title'),
            'certificates_found': ct.get('certificates_found', 0),
            'urlscan_malicious': bool(urlscan.get('malicious')),
        }

    # -- diffing -----------------------------------------------------------

    def diff(self, result: dict[str, Any]) -> dict[str, Any]:
        """
        Compare a fresh scan against the most recent stored scan.

        Args:
            result: Scan result dictionary from the scanner

        Returns:
            Delta report with 'baseline' (None on first run) and 'changes'
        """
        domain = result.get('original_domain')
        history = self.load(domain) if domain else []

        current = {
            p['domain']: self._snapshot_permutation(p)
            for p in result.get('permutations', [])
            if p.get('domain')
        }

        if not history:
            # First run establishes the baseline. Reporting seventy domains as
            # "new" would be noise, not signal, so they are counted instead.
            return {
                'domain': domain,
                'baseline': None,
                'first_run': True,
                'changes': [],
                'counts': {NEW: 0, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0},
                'total_current': len(current),
            }

        previous_scan = history[0]
        previous = previous_scan.get('permutations', {})
        changes: list[dict[str, Any]] = []

        for name, now in current.items():
            before = previous.get(name)

            if before is None:
                changes.append({
                    'kind': NEW,
                    'domain': name,
                    'risk_score': now.get('risk_score'),
                    'detail': self._describe_new(now),
                    'current': now,
                })
                continue

            changes.extend(self._compare(name, before, now))

        for name, before in previous.items():
            if name not in current:
                changes.append({
                    'kind': RESOLVED,
                    'domain': name,
                    'risk_score': before.get('risk_score'),
                    'detail': 'no longer resolves',
                    'current': None,
                })

        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for change in changes:
            counts[change['kind']] = counts.get(change['kind'], 0) + 1

        changes.sort(key=lambda c: (
            SEVERITY_ORDER.index(c['kind']),
            -(c.get('risk_score') or 0),
            c['domain'],
        ))

        return {
            'domain': domain,
            'baseline': previous_scan.get('scan_date'),
            'first_run': False,
            'changes': changes,
            'counts': counts,
            'total_current': len(current),
        }

    def _compare(self, name: str, before: dict, now: dict) -> list[dict[str, Any]]:
        """Compare one permutation across two scans."""
        changes = []

        # A parked domain that starts serving content is the transition that
        # most often precedes an actual phishing campaign.
        was_live = before.get('http_active') or before.get('https_active')
        is_live = now.get('http_active') or now.get('https_active')
        if is_live and not was_live:
            changes.append({
                'kind': ACTIVATED,
                'domain': name,
                'risk_score': now.get('risk_score'),
                'detail': 'started serving content',
                'current': now,
            })

        # Newly able to send and receive mail
        if now.get('dns_mx') and not before.get('dns_mx'):
            changes.append({
                'kind': ACTIVATED,
                'domain': name,
                'risk_score': now.get('risk_score'),
                'detail': 'added mail servers (MX)',
                'current': now,
            })

        # Newly obtained a certificate
        if now.get('certificates_found', 0) > 0 and before.get('certificates_found', 0) == 0:
            changes.append({
                'kind': ACTIVATED,
                'domain': name,
                'risk_score': now.get('risk_score'),
                'detail': 'obtained a TLS certificate',
                'current': now,
            })

        if now.get('urlscan_malicious') and not before.get('urlscan_malicious'):
            changes.append({
                'kind': ESCALATED,
                'domain': name,
                'risk_score': now.get('risk_score'),
                'detail': 'flagged malicious by URLScan',
                'current': now,
            })

        old_score = before.get('risk_score')
        new_score = now.get('risk_score')
        if isinstance(old_score, (int, float)) and isinstance(new_score, (int, float)):
            if new_score - old_score >= 10:
                changes.append({
                    'kind': ESCALATED,
                    'domain': name,
                    'risk_score': new_score,
                    'detail': f'risk score rose {old_score} -> {new_score}',
                    'current': now,
                })

        # Ownership changes: a transferred lookalike often signals resale to
        # someone with a use for it
        for field, label in TRACKED_FIELDS.items():
            if field in ('risk_score', 'created_days_ago'):
                continue
            old_value, new_value = before.get(field), now.get(field)
            if old_value != new_value and (old_value or new_value):
                changes.append({
                    'kind': CHANGED,
                    'domain': name,
                    'risk_score': new_score,
                    'detail': f'{label}: {old_value or "none"} -> {new_value or "none"}',
                    'current': now,
                })

        # A changed IP can mean re-hosting onto bulletproof infrastructure
        if set(now.get('dns_a') or []) != set(before.get('dns_a') or []):
            if before.get('dns_a'):
                changes.append({
                    'kind': CHANGED,
                    'domain': name,
                    'risk_score': new_score,
                    'detail': (
                        f'IP changed: {", ".join(before.get("dns_a") or []) or "none"}'
                        f' -> {", ".join(now.get("dns_a") or []) or "none"}'
                    ),
                    'current': now,
                })

        return changes

    @staticmethod
    def _describe_new(now: dict[str, Any]) -> str:
        """Summarise why a newly seen domain matters."""
        bits = []
        age = now.get('created_days_ago')
        if isinstance(age, (int, float)):
            bits.append(f'registered {int(age)}d ago')
        if now.get('dns_mx'):
            bits.append('has MX')
        if now.get('https_active'):
            bits.append('serving HTTPS')
        elif now.get('http_active'):
            bits.append('serving HTTP')
        if now.get('tls_verified') is False:
            bits.append('invalid certificate')
        return 'newly detected' + (' (' + ', '.join(bits) + ')' if bits else '')


def summarize(deltas: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Combine per-domain deltas into one run-level summary.

    Args:
        deltas: Delta reports, one per monitored domain

    Returns:
        Aggregate counts, the full change list, and whether anything is worth
        alerting on
    """
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    changes: list[dict[str, Any]] = []
    first_runs = []

    for delta in deltas:
        if delta.get('first_run'):
            first_runs.append(delta.get('domain'))
            continue
        for kind, n in (delta.get('counts') or {}).items():
            counts[kind] = counts.get(kind, 0) + n
        for change in delta.get('changes', []):
            changes.append({**change, 'monitored_domain': delta.get('domain')})

    changes.sort(key=lambda c: (
        SEVERITY_ORDER.index(c['kind']),
        -(c.get('risk_score') or 0),
        c['domain'],
    ))

    # RESOLVED alone is not worth waking anyone up for
    actionable = counts[NEW] + counts[ESCALATED] + counts[ACTIVATED] + counts[CHANGED]

    return {
        'counts': counts,
        'changes': changes,
        'first_runs': first_runs,
        'total_changes': len(changes),
        'actionable': actionable,
        'has_alerts': actionable > 0,
    }

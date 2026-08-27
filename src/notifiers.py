"""
Alert delivery for scan deltas.

Notifiers fire on *changes*, never on the full result set. A daily scan that
re-reported the same seventy registered lookalikes every morning would be
ignored within a week; one that says "a new lookalike appeared three days ago
and it has MX records" gets read.

All notifier payloads carry third-party data (domain names, registrant fields,
page titles), so every notifier escapes or plain-texts its content the same way
the exporters do.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import json
import logging
import smtplib
from abc import ABC, abstractmethod
from email.message import EmailMessage
from html import escape
from typing import Any

import aiohttp

from state import ACTIVATED, CHANGED, ESCALATED, NEW, RESOLVED

# Presentation per change kind: (emoji, human label, hex colour)
KIND_STYLE = {
    NEW: ('🆕', 'New', '#d73a49'),
    ESCALATED: ('⚠️', 'Escalated', '#e36209'),
    ACTIVATED: ('🔔', 'Activated', '#dbab09'),
    CHANGED: ('✏️', 'Changed', '#0366d6'),
    RESOLVED: ('✅', 'Resolved', '#28a745'),
}

# Cap on how many individual changes a single message enumerates
MAX_ITEMS = 25


def _plain(value: Any, limit: int = 120) -> str:
    """
    Flatten untrusted text for safe inclusion in a message body.

    Strips control characters and markup-significant characters that could
    forge formatting or embed links in a chat client.
    """
    text = str(value or '')
    text = ''.join(ch for ch in text if ch.isprintable())
    for ch in ('`', '*', '_', '~', '|', '<', '>', '[', ']'):
        text = text.replace(ch, ' ')
    text = ' '.join(text.split())
    return text[:limit]


def build_lines(summary: dict[str, Any]) -> list[str]:
    """Render a delta summary as plain-text bullet lines."""
    lines = []
    for change in summary.get('changes', [])[:MAX_ITEMS]:
        emoji, label, _ = KIND_STYLE.get(change['kind'], ('•', change['kind'], '#666'))
        score = change.get('risk_score')
        score_text = f" [risk {score}]" if isinstance(score, (int, float)) else ''
        lines.append(
            f"{emoji} {label}: {_plain(change['domain'], 80)}{score_text}"
            f" — {_plain(change.get('detail'), 100)}"
        )

    remaining = summary.get('total_changes', 0) - MAX_ITEMS
    if remaining > 0:
        lines.append(f"…and {remaining} more change(s); see the full report.")

    return lines


def build_headline(summary: dict[str, Any]) -> str:
    """Render a one-line summary of what changed."""
    counts = summary.get('counts', {})
    parts = [
        f"{counts.get(kind, 0)} {KIND_STYLE[kind][1].lower()}"
        for kind in (NEW, ESCALATED, ACTIVATED, CHANGED)
        if counts.get(kind, 0)
    ]
    return ', '.join(parts) if parts else 'no changes'


class BaseNotifier(ABC):
    """Base class for alert channels."""

    name = 'base'

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    async def send(self, summary: dict[str, Any], session: aiohttp.ClientSession) -> bool:
        """
        Deliver an alert.

        Args:
            summary: Aggregate delta summary
            session: Shared aiohttp session

        Returns:
            True when delivery succeeded
        """

    async def _post_json(
        self, url: str, payload: dict, session: aiohttp.ClientSession
    ) -> bool:
        """POST a JSON body, treating any 2xx as success."""
        try:
            timeout = aiohttp.ClientTimeout(total=self.config.notify_timeout)
            async with session.post(url, json=payload, timeout=timeout) as response:
                if 200 <= response.status < 300:
                    self.logger.info(f"{self.name} alert delivered")
                    return True
                body = (await response.text())[:200]
                self.logger.error(
                    f"{self.name} alert failed: HTTP {response.status} {body}"
                )
                return False
        except Exception as e:
            self.logger.error(f"{self.name} alert failed: {e}")
            return False


class SlackNotifier(BaseNotifier):
    """Post delta alerts to a Slack incoming webhook."""

    name = 'Slack'

    async def send(self, summary, session) -> bool:
        url = self.config.slack_webhook_url
        if not url:
            return False

        headline = build_headline(summary)
        lines = build_lines(summary)

        blocks = [
            {
                'type': 'header',
                'text': {
                    'type': 'plain_text',
                    'text': f'🎯 Typo Sniper: {headline}',
                },
            }
        ]

        if lines:
            # Slack caps a section at 3000 characters
            body = '\n'.join(lines)[:2900]
            blocks.append({
                'type': 'section',
                'text': {'type': 'mrkdwn', 'text': body},
            })

        blocks.append({
            'type': 'context',
            'elements': [{
                'type': 'mrkdwn',
                'text': (
                    f"{summary.get('total_changes', 0)} change(s) across "
                    f"monitored domains"
                ),
            }],
        })

        return await self._post_json(
            url, {'text': f'Typo Sniper: {headline}', 'blocks': blocks}, session
        )


class DiscordNotifier(BaseNotifier):
    """Post delta alerts to a Discord webhook."""

    name = 'Discord'

    async def send(self, summary, session) -> bool:
        url = self.config.discord_webhook_url
        if not url:
            return False

        headline = build_headline(summary)
        lines = build_lines(summary)

        # Colour the embed by the most severe change present
        colour = 0x28A745
        for kind in (NEW, ESCALATED, ACTIVATED, CHANGED):
            if summary.get('counts', {}).get(kind):
                colour = int(KIND_STYLE[kind][2].lstrip('#'), 16)
                break

        embed = {
            'title': f'🎯 Typo Sniper: {headline}',
            'color': colour,
            'description': '\n'.join(lines)[:4000] or 'No changes to report.',
            'footer': {'text': f"{summary.get('total_changes', 0)} change(s)"},
        }

        return await self._post_json(url, {'embeds': [embed]}, session)


class WebhookNotifier(BaseNotifier):
    """
    POST the delta summary to a generic HTTP endpoint as JSON.

    Unlike the chat notifiers, this one deliberately sends values verbatim.
    The consumer is a machine — a SIEM, a ticketing system, a script — and a
    domain name is the primary key it will correlate on, so mangling
    ``g00gle<script>.com`` into something prettier would corrupt the very
    field that matters. JSON encoding already prevents the payload from
    breaking out of its structure; escaping for presentation is the
    consumer's job at the point of rendering.
    """

    name = 'Webhook'

    async def send(self, summary, session) -> bool:
        url = self.config.webhook_url
        if not url:
            return False

        payload = {
            'source': 'typo-sniper',
            'headline': build_headline(summary),
            'counts': summary.get('counts', {}),
            'total_changes': summary.get('total_changes', 0),
            'changes': [
                {
                    'kind': c['kind'],
                    'domain': c['domain'],
                    'monitored_domain': c.get('monitored_domain'),
                    'risk_score': c.get('risk_score'),
                    'detail': c.get('detail'),
                }
                for c in summary.get('changes', [])
            ],
        }

        headers = {}
        if self.config.webhook_auth_header:
            # Split once so a bearer token containing ":" survives intact
            key, _, value = self.config.webhook_auth_header.partition(':')
            if value:
                headers[key.strip()] = value.strip()

        try:
            timeout = aiohttp.ClientTimeout(total=self.config.notify_timeout)
            async with session.post(
                url, json=payload, headers=headers, timeout=timeout
            ) as response:
                if 200 <= response.status < 300:
                    self.logger.info('Webhook alert delivered')
                    return True
                self.logger.error(f'Webhook alert failed: HTTP {response.status}')
                return False
        except Exception as e:
            self.logger.error(f'Webhook alert failed: {e}')
            return False


class EmailNotifier(BaseNotifier):
    """Send delta alerts over SMTP."""

    name = 'Email'

    async def send(self, summary, session) -> bool:
        if not (self.config.smtp_host and self.config.email_to):
            return False

        import asyncio

        # smtplib is blocking; keep it off the event loop
        return await asyncio.get_event_loop().run_in_executor(
            None, self._send_sync, summary
        )

    def _send_sync(self, summary: dict[str, Any]) -> bool:
        """Build and deliver the message synchronously."""
        headline = build_headline(summary)
        lines = build_lines(summary)

        message = EmailMessage()
        message['Subject'] = f'[Typo Sniper] {headline}'
        message['From'] = self.config.email_from or self.config.smtp_username
        message['To'] = ', '.join(
            a.strip() for a in self.config.email_to.split(',') if a.strip()
        )
        message.set_content(
            'Typo Sniper detected the following changes:\n\n'
            + '\n'.join(lines)
            + '\n\nSee the attached report directory for full detail.\n'
        )

        rows = ''.join(
            f'<tr><td>{escape(KIND_STYLE.get(c["kind"], ("", c["kind"], ""))[1])}</td>'
            f'<td><code>{escape(_plain(c["domain"], 80))}</code></td>'
            f'<td>{escape(str(c.get("risk_score") or ""))}</td>'
            f'<td>{escape(_plain(c.get("detail"), 120))}</td></tr>'
            for c in summary.get('changes', [])[:MAX_ITEMS]
        )
        message.add_alternative(
            f'<html><body><h2>Typo Sniper: {escape(headline)}</h2>'
            '<table border="1" cellpadding="6" cellspacing="0">'
            '<tr><th>Change</th><th>Domain</th><th>Risk</th><th>Detail</th></tr>'
            f'{rows}</table></body></html>',
            subtype='html',
        )

        try:
            if self.config.smtp_use_ssl:
                server = smtplib.SMTP_SSL(
                    self.config.smtp_host, self.config.smtp_port, timeout=30
                )
            else:
                server = smtplib.SMTP(
                    self.config.smtp_host, self.config.smtp_port, timeout=30
                )

            with server:
                if self.config.smtp_use_tls and not self.config.smtp_use_ssl:
                    server.starttls()
                if self.config.smtp_username:
                    server.login(self.config.smtp_username, self.config.smtp_password or '')
                server.send_message(message)

            self.logger.info('Email alert delivered')
            return True
        except Exception as e:
            # The exception type only: SMTP errors can echo message content
            self.logger.error(f'Email alert failed ({type(e).__name__})')
            return False


NOTIFIERS = {
    'slack': SlackNotifier,
    'discord': DiscordNotifier,
    'webhook': WebhookNotifier,
    'email': EmailNotifier,
}


async def dispatch(
    summary: dict[str, Any], config, session: aiohttp.ClientSession
) -> dict[str, bool]:
    """
    Send the delta summary through every configured channel.

    Args:
        summary: Aggregate delta summary
        config: Configuration object
        session: Shared aiohttp session

    Returns:
        Mapping of channel name to delivery success
    """
    logger = logging.getLogger(__name__)

    if not config.enable_notifications:
        return {}

    if not summary.get('has_alerts') and not config.notify_on_no_changes:
        logger.debug('No actionable changes; skipping notifications')
        return {}

    if summary.get('actionable', 0) < config.notify_min_changes:
        logger.debug(
            f"Only {summary.get('actionable', 0)} change(s), below "
            f"notify_min_changes={config.notify_min_changes}"
        )
        return {}

    results = {}
    for name in config.notify_channels:
        notifier_cls = NOTIFIERS.get(name.lower())
        if not notifier_cls:
            logger.warning(f'Unknown notification channel: {name}')
            continue
        results[name] = await notifier_cls(config).send(summary, session)

    return results


def write_delta_json(summary: dict[str, Any], path) -> None:
    """Write the delta summary to disk for downstream tooling."""
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

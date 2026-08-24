"""Tests for alert formatting, gating, and delivery."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from notifiers import (
    DiscordNotifier,
    EmailNotifier,
    SlackNotifier,
    WebhookNotifier,
    _plain,
    build_headline,
    build_lines,
    dispatch,
)
from state import ACTIVATED, CHANGED, ESCALATED, NEW, RESOLVED


def summary(changes=None, counts=None, actionable=None):
    changes = changes or []
    counts = counts or {NEW: 0, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}
    computed = counts[NEW] + counts[ESCALATED] + counts[ACTIVATED] + counts[CHANGED]
    return {
        'counts': counts,
        'changes': changes,
        'first_runs': [],
        'total_changes': len(changes),
        'actionable': computed if actionable is None else actionable,
        'has_alerts': (computed if actionable is None else actionable) > 0,
    }


HOSTILE_CHANGE = {
    'kind': NEW,
    'domain': 'evil`*_~|<>[].com',
    'risk_score': 90,
    'detail': 'newly detected <script>alert(1)</script>',
    'monitored_domain': 'brand.com',
}


def make_session(status=200, body=''):
    response = MagicMock()
    response.status = status
    response.text = AsyncMock(return_value=body)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=response)
    ctx.__aexit__ = AsyncMock(return_value=False)
    session = MagicMock()
    session.post = MagicMock(return_value=ctx)
    return session


class TestPlainText:
    def test_strips_markup_significant_characters(self):
        """Chat clients would otherwise render attacker-chosen formatting."""
        cleaned = _plain('a`b*c_d~e|f<g>h[i]j')
        for ch in '`*_~|<>[]':
            assert ch not in cleaned

    def test_strips_control_characters(self):
        assert '\x00' not in _plain('bad\x00value')
        assert '\n' not in _plain('two\nlines')

    def test_truncates(self):
        assert len(_plain('x' * 500, limit=50)) == 50

    def test_handles_none(self):
        assert _plain(None) == ''


class TestFormatting:
    def test_headline_lists_counts(self):
        text = build_headline(summary(counts={
            NEW: 2, ESCALATED: 1, ACTIVATED: 0, CHANGED: 0, RESOLVED: 4
        }))
        assert '2 new' in text
        assert '1 escalated' in text
        # Resolved is not alert-worthy and stays out of the headline
        assert 'resolved' not in text

    def test_headline_when_nothing_changed(self):
        assert build_headline(summary()) == 'no changes'

    def test_lines_include_domain_and_detail(self):
        lines = build_lines(summary(changes=[{
            'kind': NEW, 'domain': 'evil.com', 'risk_score': 80,
            'detail': 'registered 2d ago',
        }]))
        assert 'evil.com' in lines[0]
        assert 'risk 80' in lines[0]
        assert 'registered 2d ago' in lines[0]

    def test_lines_sanitise_untrusted_content(self):
        lines = build_lines(summary(changes=[HOSTILE_CHANGE]))
        assert '<script>' not in lines[0]
        assert '`' not in lines[0]

    def test_long_change_lists_are_truncated(self):
        changes = [
            {'kind': NEW, 'domain': f'd{i}.com', 'risk_score': 10, 'detail': 'x'}
            for i in range(40)
        ]
        lines = build_lines(summary(changes=changes))
        assert len(lines) == 26  # 25 items plus the "and N more" line
        assert 'more change' in lines[-1]


class TestSlackNotifier:
    @pytest.mark.asyncio
    async def test_posts_blocks(self, config):
        config.slack_webhook_url = 'https://hooks.slack.test/abc'
        session = make_session()

        assert await SlackNotifier(config).send(
            summary(changes=[HOSTILE_CHANGE], counts={
                NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}),
            session,
        ) is True

        payload = session.post.call_args.kwargs['json']
        assert 'blocks' in payload
        assert '<script>' not in str(payload)

    @pytest.mark.asyncio
    async def test_without_url_does_nothing(self, config):
        config.slack_webhook_url = None
        assert await SlackNotifier(config).send(summary(), make_session()) is False

    @pytest.mark.asyncio
    async def test_http_error_reported_as_failure(self, config):
        config.slack_webhook_url = 'https://hooks.slack.test/abc'
        assert await SlackNotifier(config).send(
            summary(), make_session(status=500, body='boom')
        ) is False

    @pytest.mark.asyncio
    async def test_network_error_reported_as_failure(self, config):
        config.slack_webhook_url = 'https://hooks.slack.test/abc'
        session = MagicMock()
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=OSError('unreachable'))
        ctx.__aexit__ = AsyncMock(return_value=False)
        session.post = MagicMock(return_value=ctx)
        assert await SlackNotifier(config).send(summary(), session) is False


class TestDiscordNotifier:
    @pytest.mark.asyncio
    async def test_posts_embed(self, config):
        config.discord_webhook_url = 'https://discord.test/api/webhooks/1/x'
        session = make_session()

        assert await DiscordNotifier(config).send(
            summary(changes=[HOSTILE_CHANGE],
                    counts={NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}),
            session,
        ) is True

        embed = session.post.call_args.kwargs['json']['embeds'][0]
        assert 'Typo Sniper' in embed['title']
        assert isinstance(embed['color'], int)

    @pytest.mark.asyncio
    async def test_colour_reflects_most_severe_change(self, config):
        config.discord_webhook_url = 'https://discord.test/api/webhooks/1/x'
        session = make_session()
        await DiscordNotifier(config).send(
            summary(changes=[{'kind': NEW, 'domain': 'a.com', 'detail': 'x'}],
                    counts={NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}),
            session,
        )
        assert session.post.call_args.kwargs['json']['embeds'][0]['color'] == 0xD73A49


class TestWebhookNotifier:
    @pytest.mark.asyncio
    async def test_posts_structured_payload(self, config):
        config.webhook_url = 'https://example.test/hook'
        session = make_session()

        assert await WebhookNotifier(config).send(
            summary(changes=[HOSTILE_CHANGE],
                    counts={NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}),
            session,
        ) is True

        payload = session.post.call_args.kwargs['json']
        assert payload['source'] == 'typo-sniper'
        assert payload['changes'][0]['monitored_domain'] == 'brand.com'

    @pytest.mark.asyncio
    async def test_auth_header_is_applied(self, config):
        config.webhook_url = 'https://example.test/hook'
        config.webhook_auth_header = 'Authorization: Bearer abc:123'
        session = make_session()

        await WebhookNotifier(config).send(summary(), session)
        headers = session.post.call_args.kwargs['headers']
        # Split once, so a token containing ':' survives
        assert headers['Authorization'] == 'Bearer abc:123'

    @pytest.mark.asyncio
    async def test_malformed_auth_header_is_ignored(self, config):
        config.webhook_url = 'https://example.test/hook'
        config.webhook_auth_header = 'no-colon-here'
        session = make_session()
        await WebhookNotifier(config).send(summary(), session)
        assert session.post.call_args.kwargs['headers'] == {}


class TestEmailNotifier:
    @pytest.mark.asyncio
    async def test_without_config_does_nothing(self, config):
        config.smtp_host = None
        assert await EmailNotifier(config).send(summary(), MagicMock()) is False

    def test_message_escapes_untrusted_html(self, config, monkeypatch):
        config.smtp_host = 'smtp.test'
        config.email_to = 'soc@example.com'
        config.email_from = 'sniper@example.com'

        captured = {}

        class FakeSMTP:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self):
                pass

            def login(self, *a):
                pass

            def send_message(self, msg):
                captured['msg'] = msg

        monkeypatch.setattr('smtplib.SMTP', FakeSMTP)

        assert EmailNotifier(config)._send_sync(
            summary(changes=[HOSTILE_CHANGE],
                    counts={NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0})
        ) is True

        body = str(captured['msg'])
        assert '<script>alert(1)</script>' not in body

    def test_smtp_failure_is_reported(self, config, monkeypatch):
        config.smtp_host = 'smtp.test'
        config.email_to = 'soc@example.com'
        monkeypatch.setattr(
            'smtplib.SMTP',
            MagicMock(side_effect=OSError('connection refused')),
        )
        assert EmailNotifier(config)._send_sync(summary()) is False


class TestDispatchGating:
    @pytest.mark.asyncio
    async def test_disabled_sends_nothing(self, config):
        config.enable_notifications = False
        config.notify_channels = ['slack']
        assert await dispatch(summary(), config, make_session()) == {}

    @pytest.mark.asyncio
    async def test_no_changes_sends_nothing(self, config):
        """The whole point is alerting on deltas, not on steady state."""
        config.enable_notifications = True
        config.notify_channels = ['slack']
        config.slack_webhook_url = 'https://hooks.slack.test/x'
        assert await dispatch(summary(), config, make_session()) == {}

    @pytest.mark.asyncio
    async def test_min_changes_threshold_is_respected(self, config):
        config.enable_notifications = True
        config.notify_channels = ['slack']
        config.slack_webhook_url = 'https://hooks.slack.test/x'
        config.notify_min_changes = 5

        result = await dispatch(
            summary(changes=[HOSTILE_CHANGE],
                    counts={NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}),
            config, make_session(),
        )
        assert result == {}

    @pytest.mark.asyncio
    async def test_sends_when_threshold_met(self, config):
        config.enable_notifications = True
        config.notify_channels = ['slack']
        config.slack_webhook_url = 'https://hooks.slack.test/x'
        config.notify_min_changes = 1

        result = await dispatch(
            summary(changes=[HOSTILE_CHANGE],
                    counts={NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}),
            config, make_session(),
        )
        assert result == {'slack': True}

    @pytest.mark.asyncio
    async def test_unknown_channel_is_skipped(self, config):
        config.enable_notifications = True
        config.notify_channels = ['carrier-pigeon']
        result = await dispatch(
            summary(changes=[HOSTILE_CHANGE],
                    counts={NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}),
            config, make_session(),
        )
        assert result == {}

    @pytest.mark.asyncio
    async def test_notify_on_no_changes_opt_in(self, config):
        config.enable_notifications = True
        config.notify_channels = ['slack']
        config.slack_webhook_url = 'https://hooks.slack.test/x'
        config.notify_on_no_changes = True
        config.notify_min_changes = 0

        assert await dispatch(summary(), config, make_session()) == {'slack': True}


class TestSanitisationBoundary:
    """Chat channels render markup; machine consumers need exact values."""

    @pytest.mark.asyncio
    async def test_chat_channels_neutralise_markup(self, config):
        config.slack_webhook_url = 'https://hooks.slack.test/x'
        config.discord_webhook_url = 'https://discord.test/x'

        for notifier_cls in (SlackNotifier, DiscordNotifier):
            session = make_session()
            await notifier_cls(config).send(
                summary(changes=[HOSTILE_CHANGE],
                        counts={NEW: 1, ESCALATED: 0, ACTIVATED: 0,
                                CHANGED: 0, RESOLVED: 0}),
                session,
            )
            body = str(session.post.call_args.kwargs['json'])
            assert '<script>' not in body
            assert '`' not in body

    @pytest.mark.asyncio
    async def test_json_webhook_preserves_the_exact_domain(self, config):
        """A SIEM correlates on the domain; a mangled value would be wrong."""
        config.webhook_url = 'https://example.test/hook'
        session = make_session()

        await WebhookNotifier(config).send(
            summary(changes=[HOSTILE_CHANGE],
                    counts={NEW: 1, ESCALATED: 0, ACTIVATED: 0,
                            CHANGED: 0, RESOLVED: 0}),
            session,
        )

        payload = session.post.call_args.kwargs['json']
        assert payload['changes'][0]['domain'] == HOSTILE_CHANGE['domain']

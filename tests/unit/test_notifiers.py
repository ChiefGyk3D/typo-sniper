"""Tests for alert formatting, gating, and delivery."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from typo_sniper.notifiers import (
    DiscordNotifier,
    EmailNotifier,
    JiraNotifier,
    MatrixNotifier,
    SlackNotifier,
    TeamsNotifier,
    WebhookNotifier,
    _plain,
    build_headline,
    build_lines,
    dispatch,
)
from typo_sniper.state import ACTIVATED, CHANGED, ESCALATED, NEW, RESOLVED


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


def make_session(status=200, body='', json_body=None):
    """
    A stub aiohttp session.

    Every notifier goes through session.request, including the ones that only
    ever POST, so that one mock covers Slack's POST and Matrix's PUT alike.
    """
    response = MagicMock()
    response.status = status
    response.text = AsyncMock(return_value=body)
    response.json = AsyncMock(return_value=json_body if json_body is not None else {})
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=response)
    ctx.__aexit__ = AsyncMock(return_value=False)
    session = MagicMock()
    session.request = MagicMock(return_value=ctx)
    # WebhookNotifier bypasses the shared helper so it can send headers
    # verbatim, so the stub answers on both.
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

        payload = session.request.call_args.kwargs['json']
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
        session.request = MagicMock(return_value=ctx)
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

        embed = session.request.call_args.kwargs['json']['embeds'][0]
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
        assert session.request.call_args.kwargs['json']['embeds'][0]['color'] == 0xD73A49


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
            body = str(session.request.call_args.kwargs['json'])
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


NEW_COUNTS = {NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}


class TestTeamsNotifier:
    @pytest.mark.asyncio
    async def test_sends_an_adaptive_card(self, config):
        config.teams_webhook_url = 'https://prod-1.westus.logic.azure.test/workflows/x'
        session = make_session()

        assert await TeamsNotifier(config).send(
            summary(changes=[HOSTILE_CHANGE], counts=NEW_COUNTS), session
        ) is True

        payload = session.request.call_args.kwargs['json']
        assert payload['type'] == 'message'
        attachment = payload['attachments'][0]
        assert attachment['contentType'] == 'application/vnd.microsoft.card.adaptive'
        assert attachment['content']['type'] == 'AdaptiveCard'

    @pytest.mark.asyncio
    async def test_markup_is_neutralised(self, config):
        """Adaptive Cards render markdown, so raw markup must not survive."""
        config.teams_webhook_url = 'https://prod-1.westus.logic.azure.test/workflows/x'
        session = make_session()
        await TeamsNotifier(config).send(
            summary(changes=[HOSTILE_CHANGE], counts=NEW_COUNTS), session
        )
        body = str(session.request.call_args.kwargs['json'])
        assert '<script>' not in body
        assert '`' not in body

    @pytest.mark.asyncio
    async def test_without_url_does_nothing(self, config):
        config.teams_webhook_url = None
        assert await TeamsNotifier(config).send(summary(), make_session()) is False

    @pytest.mark.asyncio
    async def test_http_error_is_a_failure(self, config):
        config.teams_webhook_url = 'https://prod-1.westus.logic.azure.test/workflows/x'
        assert await TeamsNotifier(config).send(
            summary(), make_session(status=400, body='bad card')
        ) is False


class TestMatrixNotifier:
    def _configure(self, config):
        config.matrix_homeserver = 'https://matrix.example.test/'
        config.matrix_access_token = 'syt_secret_token'
        config.matrix_room_id = '!abc:example.test'

    @pytest.mark.asyncio
    async def test_puts_to_the_room_send_endpoint(self, config):
        self._configure(config)
        session = make_session()

        assert await MatrixNotifier(config).send(
            summary(changes=[HOSTILE_CHANGE], counts=NEW_COUNTS), session
        ) is True

        method, url = session.request.call_args.args[:2]
        assert method == 'PUT'
        assert '/_matrix/client/v3/rooms/' in url
        assert '/send/m.room.message/' in url

    @pytest.mark.asyncio
    async def test_room_id_is_url_encoded(self, config):
        """A room ID starts with ! and contains :, both of which need escaping."""
        self._configure(config)
        session = make_session()
        await MatrixNotifier(config).send(summary(), session)

        url = session.request.call_args.args[1]
        assert '%21abc%3Aexample.test' in url

    @pytest.mark.asyncio
    async def test_token_is_sent_as_a_header_not_in_the_url(self, config):
        """A query-parameter token lands in homeserver and proxy logs."""
        self._configure(config)
        session = make_session()
        await MatrixNotifier(config).send(summary(), session)

        url = session.request.call_args.args[1]
        headers = session.request.call_args.kwargs['headers']
        assert 'syt_secret_token' not in url
        assert headers['Authorization'] == 'Bearer syt_secret_token'

    @pytest.mark.asyncio
    async def test_each_send_uses_a_fresh_transaction_id(self, config):
        self._configure(config)
        session = make_session()
        await MatrixNotifier(config).send(summary(), session)
        first = session.request.call_args.args[1]
        await MatrixNotifier(config).send(summary(), session)
        second = session.request.call_args.args[1]
        assert first != second

    @pytest.mark.asyncio
    async def test_html_body_escapes_untrusted_content(self, config):
        self._configure(config)
        session = make_session()
        await MatrixNotifier(config).send(
            summary(changes=[HOSTILE_CHANGE], counts=NEW_COUNTS), session
        )
        formatted = session.request.call_args.kwargs['json']['formatted_body']
        assert '<script>' not in formatted

    @pytest.mark.asyncio
    async def test_incomplete_configuration_does_nothing(self, config):
        self._configure(config)
        config.matrix_access_token = None
        assert await MatrixNotifier(config).send(summary(), make_session()) is False


def ticketable(domain='evil.com', kind=NEW, score=80):
    return {
        'kind': kind, 'domain': domain, 'risk_score': score,
        'detail': 'newly detected', 'monitored_domain': 'brand.com',
    }


class TestJiraNotifier:
    def _configure(self, config):
        config.jira_url = 'https://acme.atlassian.test'
        config.jira_email = 'security@acme.test'
        config.jira_api_token = 'token'
        config.jira_project_key = 'SEC'

    def _session(self, search_hits=0, created_key='SEC-1'):
        """A session answering a JQL search then an issue creation."""
        search = MagicMock()
        search.status = 200
        search.text = AsyncMock(return_value='')
        search.json = AsyncMock(return_value={
            'issues': [{'key': 'SEC-9'}] * search_hits
        })
        create = MagicMock()
        create.status = 201
        create.text = AsyncMock(return_value='')
        create.json = AsyncMock(return_value={'key': created_key})

        def responder(method, url, **kwargs):
            ctx = MagicMock()
            target = search if url.endswith('/search/jql') else create
            ctx.__aenter__ = AsyncMock(return_value=target)
            ctx.__aexit__ = AsyncMock(return_value=False)
            return ctx

        session = MagicMock()
        session.request = MagicMock(side_effect=responder)
        return session

    def _creates(self, session):
        return [c for c in session.request.call_args_list
                if c.args[1].endswith('/rest/api/3/issue')]

    @pytest.mark.asyncio
    async def test_creates_an_issue_for_a_new_domain(self, config):
        self._configure(config)
        session = self._session()

        assert await JiraNotifier(config).send(
            summary(changes=[ticketable()], counts=NEW_COUNTS), session
        ) is True

        creates = self._creates(session)
        assert len(creates) == 1
        fields = creates[0].kwargs['json']['fields']
        assert fields['project'] == {'key': 'SEC'}
        assert 'evil.com' in fields['summary']
        assert fields['description']['type'] == 'doc'

    @pytest.mark.asyncio
    async def test_an_already_tracked_domain_is_not_filed_twice(self, config):
        """A scheduled scan must not open a fresh ticket every morning."""
        self._configure(config)
        session = self._session(search_hits=1)

        await JiraNotifier(config).send(
            summary(changes=[ticketable()], counts=NEW_COUNTS), session
        )
        assert self._creates(session) == []

    @pytest.mark.asyncio
    async def test_the_dedupe_label_is_stable_for_a_domain(self, config):
        assert JiraNotifier.label_for('evil.com') == JiraNotifier.label_for('EVIL.com')
        assert JiraNotifier.label_for('a.com') != JiraNotifier.label_for('b.com')
        assert ' ' not in JiraNotifier.label_for('evil.com')

    @pytest.mark.asyncio
    async def test_creation_is_capped_per_run(self, config):
        """A first scan of a large brand must not bury a backlog."""
        self._configure(config)
        config.jira_max_issues_per_run = 3
        session = self._session()

        changes = [ticketable(f'evil{i}.com', score=i) for i in range(20)]
        await JiraNotifier(config).send(
            summary(changes=changes, counts={NEW: 20, ESCALATED: 0,
                                             ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}),
            session,
        )
        assert len(self._creates(session)) == 3

    @pytest.mark.asyncio
    async def test_the_cap_keeps_the_highest_risk(self, config):
        self._configure(config)
        config.jira_max_issues_per_run = 2
        session = self._session()

        changes = [ticketable('low.com', score=10), ticketable('high.com', score=95),
                   ticketable('mid.com', score=50)]
        await JiraNotifier(config).send(
            summary(changes=changes, counts={NEW: 3, ESCALATED: 0,
                                             ACTIVATED: 0, CHANGED: 0, RESOLVED: 0}),
            session,
        )
        filed = {c.kwargs['json']['fields']['summary'] for c in self._creates(session)}
        assert any('high.com' in s for s in filed)
        assert not any('low.com' in s for s in filed)

    @pytest.mark.asyncio
    async def test_a_capped_run_says_what_it_did_not_file(self, config, caplog):
        self._configure(config)
        config.jira_max_issues_per_run = 1
        session = self._session()
        await JiraNotifier(config).send(
            summary(changes=[ticketable('a.com'), ticketable('b.com')],
                    counts={NEW: 2, ESCALATED: 0, ACTIVATED: 0,
                            CHANGED: 0, RESOLVED: 0}),
            session,
        )
        assert 'were not filed' in caplog.text

    @pytest.mark.asyncio
    async def test_resolved_changes_do_not_open_tickets(self, config):
        """A domain going away is good news, not work."""
        self._configure(config)
        session = self._session()
        await JiraNotifier(config).send(
            summary(changes=[ticketable('gone.com', kind=RESOLVED)],
                    counts={NEW: 0, ESCALATED: 0, ACTIVATED: 0,
                            CHANGED: 0, RESOLVED: 1}),
            session,
        )
        assert self._creates(session) == []

    @pytest.mark.asyncio
    async def test_incomplete_configuration_does_nothing(self, config):
        self._configure(config)
        config.jira_api_token = None
        assert await JiraNotifier(config).send(
            summary(changes=[ticketable()], counts=NEW_COUNTS), make_session()
        ) is False

    @pytest.mark.asyncio
    async def test_untrusted_fields_are_neutralised_in_the_ticket(self, config):
        self._configure(config)
        session = self._session()
        await JiraNotifier(config).send(
            summary(changes=[HOSTILE_CHANGE], counts=NEW_COUNTS), session
        )
        body = str(self._creates(session)[0].kwargs['json'])
        assert '<script>' not in body

    @pytest.mark.asyncio
    async def test_credentials_are_sent_as_a_basic_header(self, config):
        """Not in the URL, where they would land in access logs."""
        import base64

        self._configure(config)
        session = self._session()
        await JiraNotifier(config).send(
            summary(changes=[ticketable()], counts=NEW_COUNTS), session
        )

        call = self._creates(session)[0]
        expected = base64.b64encode(b'security@acme.test:token').decode()
        assert call.kwargs['headers']['Authorization'] == f'Basic {expected}'
        assert 'token' not in call.args[1]

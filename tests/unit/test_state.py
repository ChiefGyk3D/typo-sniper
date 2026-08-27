"""Tests for scan history persistence and change detection."""

import pytest

from typo_sniper.state import ACTIVATED, CHANGED, ESCALATED, NEW, RESOLVED, ScanHistory, summarize


def perm(domain, **kwargs):
    """Build a permutation with sensible defaults."""
    base = {
        'domain': domain,
        'fuzzer': 'homoglyph',
        'risk_score': 20,
        'created_days_ago': 500,
        'dns_a': ['203.0.113.1'],
        'threat_intel': {},
    }
    threat = kwargs.pop('threat_intel', None)
    base.update(kwargs)
    if threat is not None:
        base['threat_intel'] = threat
    return base


def result(domain='example.com', permutations=None, scan_date='2026-01-01'):
    perms = permutations or []
    return {
        'original_domain': domain,
        'scan_date': scan_date,
        'total_permutations': len(perms),
        'registered_count': len(perms),
        'filtered_count': len(perms),
        'permutations': perms,
    }


@pytest.fixture
def history(tmp_path):
    return ScanHistory(tmp_path / 'state', retain=5)


class TestPersistence:
    def test_first_load_is_empty(self, history):
        assert history.load('example.com') == []

    def test_record_then_load(self, history):
        history.record(result(permutations=[perm('exampe.com')]))
        scans = history.load('example.com')
        assert len(scans) == 1
        assert 'exampe.com' in scans[0]['permutations']

    def test_newest_scan_is_first(self, history):
        history.record(result(scan_date='2026-01-01'))
        history.record(result(scan_date='2026-01-02'))
        assert history.load('example.com')[0]['scan_date'] == '2026-01-02'

    def test_retention_limit_is_enforced(self, history):
        for i in range(10):
            history.record(result(scan_date=f'2026-01-{i + 1:02d}'))
        assert len(history.load('example.com')) == 5

    def test_domains_are_isolated(self, history):
        history.record(result('a.com', [perm('a1.com')]))
        history.record(result('b.com', [perm('b1.com')]))
        assert 'a1.com' in history.load('a.com')[0]['permutations']
        assert 'b1.com' in history.load('b.com')[0]['permutations']

    def test_corrupt_history_degrades_to_empty(self, history):
        history.record(result())
        corrupted = next((history.state_dir).glob('*.json'))
        corrupted.write_text('{not json')
        assert history.load('example.com') == []

    def test_result_without_domain_is_ignored(self, history):
        history.record({'permutations': []})
        assert list(history.state_dir.glob('*.json')) == []


class TestFirstRun:
    def test_no_baseline_reports_no_changes(self, history):
        """Reporting 70 domains as 'new' on day one would be noise."""
        delta = history.diff(result(permutations=[perm(f'x{i}.com') for i in range(5)]))
        assert delta['first_run'] is True
        assert delta['changes'] == []
        assert delta['total_current'] == 5


class TestChangeDetection:
    def _seed(self, history, permutations):
        history.record(result(permutations=permutations))

    def test_new_domain_detected(self, history):
        self._seed(history, [perm('old.com')])
        delta = history.diff(result(permutations=[perm('old.com'), perm('brandnew.com')]))
        news = [c for c in delta['changes'] if c['kind'] == NEW]
        assert [c['domain'] for c in news] == ['brandnew.com']

    def test_new_domain_detail_mentions_signals(self, history):
        self._seed(history, [])
        delta = history.diff(result(permutations=[
            perm('evil.com', created_days_ago=3, dns_mx=['mx.evil.com'],
                 threat_intel={'http_probe': {'https_active': True}})
        ]))
        detail = delta['changes'][0]['detail']
        assert 'registered 3d ago' in detail
        assert 'has MX' in detail
        assert 'serving HTTPS' in detail

    def test_parked_domain_going_live_is_activation(self, history):
        self._seed(history, [perm('evil.com', threat_intel={})])
        delta = history.diff(result(permutations=[
            perm('evil.com', threat_intel={'http_probe': {'https_active': True}})
        ]))
        kinds = [(c['kind'], c['detail']) for c in delta['changes']]
        assert (ACTIVATED, 'started serving content') in kinds

    def test_added_mx_is_activation(self, history):
        self._seed(history, [perm('evil.com')])
        delta = history.diff(result(permutations=[perm('evil.com', dns_mx=['mx.evil.com'])]))
        assert any('mail servers' in c['detail'] for c in delta['changes'])

    def test_new_certificate_is_activation(self, history):
        self._seed(history, [perm('evil.com')])
        delta = history.diff(result(permutations=[
            perm('evil.com', threat_intel={'certificate_transparency': {'certificates_found': 2}})
        ]))
        assert any('certificate' in c['detail'] for c in delta['changes'])

    def test_urlscan_malicious_verdict_is_escalation(self, history):
        self._seed(history, [perm('evil.com')])
        delta = history.diff(result(permutations=[
            perm('evil.com', threat_intel={'urlscan': {'malicious': True}})
        ]))
        assert any(c['kind'] == ESCALATED and 'URLScan' in c['detail']
                   for c in delta['changes'])

    def test_risk_jump_is_escalation(self, history):
        self._seed(history, [perm('evil.com', risk_score=20)])
        delta = history.diff(result(permutations=[perm('evil.com', risk_score=65)]))
        assert any(c['kind'] == ESCALATED and '20 -> 65' in c['detail']
                   for c in delta['changes'])

    def test_small_risk_drift_is_not_reported(self, history):
        """A few points of noise should not page anyone."""
        self._seed(history, [perm('evil.com', risk_score=20)])
        delta = history.diff(result(permutations=[perm('evil.com', risk_score=25)]))
        assert not any(c['kind'] == ESCALATED for c in delta['changes'])

    def test_registrar_change_detected(self, history):
        self._seed(history, [perm('evil.com', whois_registrar='OldReg')])
        delta = history.diff(result(permutations=[perm('evil.com', whois_registrar='NewReg')]))
        assert any(c['kind'] == CHANGED and 'registrar' in c['detail']
                   for c in delta['changes'])

    def test_ip_change_detected(self, history):
        self._seed(history, [perm('evil.com', dns_a=['1.1.1.1'])])
        delta = history.diff(result(permutations=[perm('evil.com', dns_a=['2.2.2.2'])]))
        assert any('IP changed' in c['detail'] for c in delta['changes'])

    def test_disappeared_domain_is_resolved(self, history):
        self._seed(history, [perm('gone.com'), perm('stays.com')])
        delta = history.diff(result(permutations=[perm('stays.com')]))
        assert any(c['kind'] == RESOLVED and c['domain'] == 'gone.com'
                   for c in delta['changes'])

    def test_steady_state_produces_no_changes(self, history):
        perms = [perm('a.com'), perm('b.com')]
        self._seed(history, perms)
        delta = history.diff(result(permutations=perms))
        assert delta['changes'] == []

    def test_changes_are_ordered_by_severity_then_risk(self, history):
        self._seed(history, [perm('drift.com', whois_registrar='Old'), perm('old.com')])
        delta = history.diff(result(permutations=[
            perm('drift.com', whois_registrar='New'),
            perm('old.com'),
            perm('fresh.com', risk_score=90),
        ]))
        assert delta['changes'][0]['kind'] == NEW

    def test_counts_reflect_changes(self, history):
        self._seed(history, [perm('gone.com')])
        delta = history.diff(result(permutations=[perm('added.com')]))
        assert delta['counts'][NEW] == 1
        assert delta['counts'][RESOLVED] == 1


class TestSummarize:
    def test_aggregates_across_domains(self):
        summary = summarize([
            {'domain': 'a.com', 'first_run': False,
             'counts': {NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0},
             'changes': [{'kind': NEW, 'domain': 'x.com', 'risk_score': 50}]},
            {'domain': 'b.com', 'first_run': False,
             'counts': {NEW: 0, ESCALATED: 1, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0},
             'changes': [{'kind': ESCALATED, 'domain': 'y.com', 'risk_score': 70}]},
        ])
        assert summary['counts'][NEW] == 1
        assert summary['counts'][ESCALATED] == 1
        assert summary['total_changes'] == 2
        assert summary['has_alerts'] is True

    def test_tags_changes_with_their_monitored_domain(self):
        summary = summarize([
            {'domain': 'brand.com', 'first_run': False,
             'counts': {NEW: 1, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 0},
             'changes': [{'kind': NEW, 'domain': 'brnad.com', 'risk_score': 50}]},
        ])
        assert summary['changes'][0]['monitored_domain'] == 'brand.com'

    def test_first_runs_are_listed_not_counted(self):
        summary = summarize([{'domain': 'a.com', 'first_run': True, 'changes': []}])
        assert summary['first_runs'] == ['a.com']
        assert summary['has_alerts'] is False

    def test_resolved_alone_does_not_alert(self):
        """A squat going away is good news, not something to page on."""
        summary = summarize([
            {'domain': 'a.com', 'first_run': False,
             'counts': {NEW: 0, ESCALATED: 0, ACTIVATED: 0, CHANGED: 0, RESOLVED: 3},
             'changes': [{'kind': RESOLVED, 'domain': 'g.com', 'risk_score': 10}]},
        ])
        assert summary['has_alerts'] is False
        assert summary['total_changes'] == 1

    def test_empty_input(self):
        summary = summarize([])
        assert summary['total_changes'] == 0
        assert summary['has_alerts'] is False


class TestMailPostureChanges:
    """A squat gaining send-capable mail is the key pre-phishing transition."""

    def _seed(self, history, permutations):
        history.record(result(permutations=permutations))

    def test_becoming_send_capable_is_an_escalation(self, history):
        self._seed(history, [perm('evil.com', mail_intel={'posture': 'none'})])
        delta = history.diff(result(permutations=[
            perm('evil.com', mail_intel={'posture': 'provisioned'})
        ]))
        assert any(c['kind'] == ESCALATED and 'provisioned to send mail' in c['detail']
                   for c in delta['changes'])

    def test_gaining_only_mx_is_a_lesser_activation(self, history):
        self._seed(history, [perm('evil.com', mail_intel={'posture': 'none'})])
        delta = history.diff(result(permutations=[
            perm('evil.com', mail_intel={'posture': 'receive-only'})
        ]))
        mail_changes = [c for c in delta['changes'] if 'mail configuration' in c['detail']]
        assert mail_changes and mail_changes[0]['kind'] == ACTIVATED

    def test_hardening_further_still_escalates(self, history):
        self._seed(history, [perm('evil.com', mail_intel={'posture': 'provisioned'})])
        delta = history.diff(result(permutations=[
            perm('evil.com', mail_intel={'posture': 'hardened'})
        ]))
        assert any(c['kind'] == ESCALATED for c in delta['changes'])

    def test_losing_mail_capability_is_not_an_alert(self, history):
        """Regression, not escalation — nothing to page on."""
        self._seed(history, [perm('evil.com', mail_intel={'posture': 'hardened'})])
        delta = history.diff(result(permutations=[
            perm('evil.com', mail_intel={'posture': 'none'})
        ]))
        assert not any(c['kind'] == ESCALATED for c in delta['changes'])

    def test_new_send_capable_domain_says_so(self, history):
        self._seed(history, [])
        delta = history.diff(result(permutations=[
            perm('evil.com', mail_intel={'posture': 'hardened'})
        ]))
        assert 'SEND-CAPABLE mail' in delta['changes'][0]['detail']


def page_perm(domain, **page):
    """A permutation whose HTTP probe carries a page analysis."""
    return perm(domain, threat_intel={'http_probe': {
        'https_active': True,
        'page': {'parse_ok': True, **page},
    }})


class TestCredentialFormTransitions:
    """
    A credential form appearing is the moment a watched lookalike stops being
    a possibility and becomes a live collection point. It has to raise a
    change, not sit silently in a column.
    """

    def test_a_form_appearing_raises_an_escalation(self, history):
        history.record(result(permutations=[page_perm('evil.com')]))
        delta = history.diff(result(permutations=[
            page_perm('evil.com', is_credential_form=True, has_password_input=True)
        ]))

        escalations = [c for c in delta['changes'] if c['kind'] == ESCALATED]
        assert any('credential form' in c['detail'] for c in escalations)

    def test_a_form_that_was_already_there_raises_nothing(self, history):
        """A daily scan must not re-report the same form every morning."""
        before = page_perm('evil.com', is_credential_form=True)
        history.record(result(permutations=[before]))
        delta = history.diff(result(permutations=[page_perm(
            'evil.com', is_credential_form=True)]))

        assert not [c for c in delta['changes']
                    if 'credential form' in (c.get('detail') or '')]

    def test_a_form_starting_to_submit_off_site_raises_an_escalation(self, history):
        history.record(result(permutations=[page_perm('evil.com', form_count=1)]))
        delta = history.diff(result(permutations=[page_perm(
            'evil.com', form_count=1, external_form_action=True)]))

        assert any('submits to a different domain' in (c.get('detail') or '')
                   for c in delta['changes'])

    def test_page_findings_survive_a_history_round_trip(self, history):
        """The snapshot has to persist these or the diff can never see them."""
        history.record(result(permutations=[page_perm(
            'evil.com', is_credential_form=True, external_form_action=True)]))
        stored = history.load('example.com')[0]['permutations']['evil.com']

        assert stored['is_credential_form'] is True
        assert stored['external_form_action'] is True

    def test_domains_without_page_analysis_are_unaffected(self, history):
        history.record(result(permutations=[perm('quiet.com')]))
        delta = history.diff(result(permutations=[perm('quiet.com')]))
        assert not [c for c in delta['changes']
                    if 'form' in (c.get('detail') or '')]

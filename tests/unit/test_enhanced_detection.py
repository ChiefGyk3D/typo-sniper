"""Tests for combo-squatting, phonetic, and IDN homograph generation."""

import pytest

from enhanced_detection import (
    ComboSquattingDetector,
    IDNHomographDetector,
    SoundAlikeDetector,
    generate_enhanced_permutations,
)


class TestSplitDomain:
    @pytest.mark.parametrize('domain,expected', [
        ('example.com', ('example', 'com')),
        ('example.co.uk', ('example', 'co.uk')),
        ('shop.example.com', ('example', 'com')),
        ('example.com.au', ('example', 'com.au')),
        ('EXAMPLE.COM', ('example', 'com')),
        ('example.com.', ('example', 'com')),
    ])
    def test_split(self, domain, expected):
        assert ComboSquattingDetector.split_domain(domain) == expected


class TestComboSquats:
    def test_generates_both_orderings(self):
        variants = ComboSquattingDetector.generate_combosquats('example.com', ['login'])
        assert {
            'example-login.com',
            'login-example.com',
            'examplelogin.com',
        } <= variants

    def test_never_emits_underscores(self):
        """Underscores are invalid in hostnames and can never resolve."""
        variants = ComboSquattingDetector.generate_combosquats('example.com')
        assert not any('_' in v for v in variants)

    def test_preserves_multi_label_suffix(self):
        variants = ComboSquattingDetector.generate_combosquats('example.co.uk', ['login'])
        assert all(v.endswith('.co.uk') for v in variants)

    def test_excludes_the_original_domain(self):
        variants = ComboSquattingDetector.generate_combosquats('example.com', [''])
        assert 'example.com' not in variants

    def test_rejects_oversized_labels(self):
        variants = ComboSquattingDetector.generate_combosquats('example.com', ['x' * 70])
        assert variants == set()

    def test_default_keywords_are_deduplicated_in_output(self):
        variants = ComboSquattingDetector.generate_combosquats('example.com')
        assert len(variants) == len(set(variants))


class TestSoundAlike:
    def test_empty_input_does_not_crash(self):
        """soundex('') previously raised IndexError."""
        assert SoundAlikeDetector.soundex('') == '0000'
        assert SoundAlikeDetector.soundex('123') == '0000'

    def test_similar_names_match(self):
        assert SoundAlikeDetector.soundex('Robert') == SoundAlikeDetector.soundex('Rupert')

    def test_are_similar_handles_domains(self):
        assert SoundAlikeDetector.are_similar('example.com', 'example.net') is True

    def test_metaphone_returns_a_code(self):
        assert SoundAlikeDetector.metaphone('Thompson')


class TestIDNHomographs:
    def test_generates_punycode(self):
        variants = IDNHomographDetector.generate_homographs('example.com')
        assert variants
        assert all(v.startswith('xn--') or '.' in v for v in variants)

    def test_bounded_output(self):
        assert len(IDNHomographDetector.generate_homographs('aeiousxy.com')) <= 50

    def test_domain_without_confusables(self):
        assert IDNHomographDetector.generate_homographs('bdfg.com') == set()

    def test_is_homograph_detects_cyrillic(self):
        assert IDNHomographDetector.is_homograph('exаmple.com') is True  # Cyrillic а
        assert IDNHomographDetector.is_homograph('example.com') is False


class TestGenerateEnhancedPermutations:
    def test_disabled_features_produce_nothing(self, config):
        config.enable_combosquatting = False
        config.enable_idn_homograph = False
        assert generate_enhanced_permutations('example.com', config) == set()

    def test_combosquatting_only(self, config):
        config.enable_combosquatting = True
        config.enable_idn_homograph = False
        result = generate_enhanced_permutations('example.com', config)
        assert result
        assert all(not v.startswith('xn--') for v in result)

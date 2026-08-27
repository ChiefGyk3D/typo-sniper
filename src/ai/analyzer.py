"""
Orchestration for AI-assisted triage.

Ties the prompt builders, the provider layer, and response validation together
into two operations a scan can call:

  * ``triage`` — explain a set of findings for one monitored brand
  * ``explain_changes`` — explain what moved since the previous scan

Both are strictly additive. A failure here annotates the report with a reason
and leaves every deterministic finding intact, because AI triage is a reading
aid layered on top of the scan, never a step the scan depends on.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import logging
from typing import Any

from . import prompts
from .base import AIResult
from .providers import get_provider


class AIAnalyzer:
    """Run AI triage over scan output."""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.provider = get_provider(config) if config.enable_ai_analysis else None
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.injection_attempts: list[str] = []

    def status(self) -> tuple[bool, str]:
        """
        Report whether AI analysis can run.

        Returns:
            Tuple of (ready, reason)
        """
        if not self.config.enable_ai_analysis:
            return False, 'AI analysis is disabled'
        if self.provider is None:
            return False, (
                f"unknown AI provider '{self.config.ai_provider}'; "
                f"expected one of claude, openai, gemini, ollama"
            )
        return self.provider.available()

    async def triage(
        self, monitored_domain: str, permutations: list[dict[str, Any]]
    ) -> AIResult | None:
        """
        Explain a set of findings for one monitored domain.

        Args:
            monitored_domain: The brand domain being protected
            permutations: Findings, highest risk first

        Returns:
            AIResult, or None when analysis is not configured or not warranted
        """
        ready, reason = self.status()
        if not ready:
            self.logger.debug(f'Skipping AI triage: {reason}')
            return None

        # Only spend a request where there is something worth explaining
        worth_analysing = [
            p for p in permutations
            if (p.get('risk_score') or 0) >= self.config.ai_min_risk_score
        ]
        if not worth_analysing:
            self.logger.debug(
                f'No findings at or above risk {self.config.ai_min_risk_score}; '
                f'skipping AI triage'
            )
            return None

        result = await self.provider.analyze(
            prompts.SYSTEM_PROMPT,
            prompts.build_triage_prompt(monitored_domain, worth_analysing),
            prompts.TRIAGE_SCHEMA,
        )

        return self._post_process(result, {p['domain'] for p in worth_analysing})

    async def explain_changes(self, summary: dict[str, Any]) -> AIResult | None:
        """
        Explain what changed since the previous scan.

        Args:
            summary: Aggregate delta summary

        Returns:
            AIResult, or None when analysis is not configured or nothing changed
        """
        ready, reason = self.status()
        if not ready:
            self.logger.debug(f'Skipping AI change summary: {reason}')
            return None

        if not summary.get('changes'):
            return None

        result = await self.provider.analyze(
            prompts.SYSTEM_PROMPT,
            prompts.build_delta_prompt(summary),
            prompts.TRIAGE_SCHEMA,
        )

        known = {
            str(c.get('domain', '')) for c in summary.get('changes', [])
        }
        return self._post_process(result, known)

    def _post_process(self, result: AIResult, known_domains: set[str]) -> AIResult:
        """
        Validate and account for one result.

        Args:
            result: Raw provider result
            known_domains: Domains that were actually in the request

        Returns:
            The result with unrecognised assessments removed
        """
        if not result.ok:
            return result

        self.total_input_tokens += result.input_tokens
        self.total_output_tokens += result.output_tokens

        if result.content:
            result.content = prompts.validate_response(result.content, known_domains)

            dropped = result.content.get('dropped_assessments', 0)
            if dropped:
                # The model named domains that were not in the request. Either
                # it hallucinated them or it was steered into emitting them;
                # either way they must not reach a report.
                self.logger.warning(
                    f'Discarded {dropped} assessment(s) for domains that were '
                    f'not part of this scan'
                )

            for domain in result.injection_attempts:
                if domain and domain not in self.injection_attempts:
                    self.injection_attempts.append(domain)
                    self.logger.warning(
                        f'{domain} carried text resembling an instruction to the '
                        f'analysis system, which is itself a signal of intent'
                    )

        return result

    def usage_summary(self) -> dict[str, Any]:
        """Token spend and notable observations from this run."""
        return {
            'provider': self.config.ai_provider if self.provider else None,
            'model': self.config.ai_model,
            'input_tokens': self.total_input_tokens,
            'output_tokens': self.total_output_tokens,
            'injection_attempts': list(self.injection_attempts),
        }

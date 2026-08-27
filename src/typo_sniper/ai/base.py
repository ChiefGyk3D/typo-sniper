"""
Provider-agnostic interface for AI-assisted triage.

Every provider is optional. Typo Sniper's core detection is deterministic and
must keep working with no AI configured at all, so nothing here is imported at
module load and a missing SDK degrades to "AI analysis unavailable" rather
than a crash.

What the AI layer is allowed to do, and what it is not:

  * It **explains**. Given findings and a deterministic risk score, it says
    what the combination of signals suggests and how confident that reading is.
  * It **does not score**. Risk scores stay reproducible and defensible; an
    analyst has to be able to justify a number in a takedown request, and
    "the model said 85" is not a justification. A hallucinated score in an
    abuse report is worse than no score.
  * It **does not decide**. Suggested actions are advisory, and the report
    marks them as model output.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AIResult:
    """Outcome of one analysis request."""

    ok: bool
    provider: str
    model: str
    content: dict[str, Any] = field(default_factory=dict)
    text: str = ''
    error: str | None = None
    # Token accounting, where the provider reports it
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def injection_attempts(self) -> list[str]:
        """Domains whose own data tried to steer the analysis."""
        return [
            a.get('domain', '')
            for a in self.content.get('assessments', [])
            if a.get('injection_attempt_observed')
        ]


class AIProvider(ABC):
    """Base class for AI analysis backends."""

    name = 'base'
    #: Import path of the SDK this provider needs, or None if it uses plain HTTP
    sdk_module: str | None = None
    #: pip extra that installs the SDK
    install_hint = ''

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(f'ai.{self.name}')

    # -- availability ------------------------------------------------------

    @classmethod
    def sdk_available(cls) -> bool:
        """Whether this provider's SDK is importable."""
        if cls.sdk_module is None:
            return True
        import importlib.util

        return importlib.util.find_spec(cls.sdk_module) is not None

    @abstractmethod
    def credentials_available(self) -> bool:
        """Whether the provider has what it needs to authenticate."""

    def available(self) -> tuple[bool, str]:
        """
        Report whether this provider can run, and why not if it cannot.

        Returns:
            Tuple of (available, reason)
        """
        if not self.sdk_available():
            return False, (
                f"{self.name} SDK is not installed"
                + (f" (pip install 'typo-sniper[{self.install_hint}]')"
                   if self.install_hint else '')
            )
        if not self.credentials_available():
            return False, f"{self.name} credentials are not configured"
        return True, ''

    # -- analysis ----------------------------------------------------------

    @abstractmethod
    async def analyze(
        self, system: str, prompt: str, schema: dict[str, Any] | None = None
    ) -> AIResult:
        """
        Send one analysis request.

        Args:
            system: System prompt (trusted; never contains scan data)
            prompt: User turn containing the delimited, neutralised findings
            schema: JSON schema constraining the response, when supported

        Returns:
            AIResult, with ok=False and an error message on failure
        """

    # -- helpers -----------------------------------------------------------

    def _parse_json(self, text: str) -> dict[str, Any]:
        """
        Recover a JSON object from a model response.

        Providers without native structured output return prose that may wrap
        the JSON in a code fence or commentary.

        Args:
            text: Raw response text

        Returns:
            Parsed object, or an empty dict when nothing parses
        """
        import json
        import re

        text = (text or '').strip()

        fenced = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if fenced:
            text = fenced.group(1)

        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            pass

        # Last resort: the outermost braces
        start, end = text.find('{'), text.rfind('}')
        if 0 <= start < end:
            try:
                parsed = json.loads(text[start:end + 1])
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                pass

        self.logger.debug('Could not parse a JSON object from the response')
        return {}

    def _failure(self, error: str, model: str = '') -> AIResult:
        """Build a failed result without raising."""
        self.logger.error(f'{self.name} analysis failed: {error}')
        return AIResult(
            ok=False, provider=self.name, model=model or self.config.ai_model,
            error=error,
        )

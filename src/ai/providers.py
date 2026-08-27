"""
AI provider implementations.

Four backends, chosen so that the feature is usable both by teams with a
vendor account and by teams whose scan data may not leave their network:

  * Claude    - official ``anthropic`` SDK
  * OpenAI    - official ``openai`` SDK
  * Gemini    - official ``google-genai`` SDK
  * Ollama    - plain HTTP to a local daemon, no SDK, no data leaving the host

The Ollama option is not an afterthought. Scan output contains the domains an
organisation is defending, which is itself sensitive: it reveals what they own
and what they are worried about. Some teams cannot send that to a third party,
and for them a local model is the difference between using this feature and
disabling it.

Every SDK is imported lazily inside the call, so an unconfigured provider
costs nothing and a missing package degrades to a clear message.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

from typing import Any

from .base import AIProvider, AIResult


class ClaudeProvider(AIProvider):
    """Analysis via the Anthropic Messages API."""

    name = 'claude'
    sdk_module = 'anthropic'
    install_hint = 'claude'
    default_model = 'claude-opus-5'

    def credentials_available(self) -> bool:
        return bool(self.config.ai_api_key)

    async def analyze(self, system, prompt, schema=None) -> AIResult:
        import anthropic

        model = self.config.ai_model or self.default_model

        try:
            client = anthropic.AsyncAnthropic(
                api_key=self.config.ai_api_key,
                timeout=self.config.ai_timeout,
                max_retries=2,
            )

            kwargs: dict[str, Any] = {
                'model': model,
                'max_tokens': self.config.ai_max_tokens,
                'system': system,
                'messages': [{'role': 'user', 'content': prompt}],
                # Adaptive thinking: the model decides how much reasoning the
                # request warrants. budget_tokens is rejected on current models.
                'thinking': {'type': 'adaptive'},
                'output_config': {'effort': self.config.ai_effort},
            }

            if schema:
                kwargs['output_config']['format'] = {
                    'type': 'json_schema',
                    'schema': schema,
                }

            # Streaming keeps a long reasoning turn from hitting the HTTP timeout
            async with client.messages.stream(**kwargs) as stream:
                message = await stream.get_final_message()

            # A safety decline arrives as HTTP 200; check before reading content
            if message.stop_reason == 'refusal':
                details = getattr(message, 'stop_details', None)
                return self._failure(
                    f"model declined the request"
                    f"{f' ({details.category})' if details else ''}",
                    model,
                )

            text = ''.join(
                block.text for block in message.content
                if getattr(block, 'type', None) == 'text'
            )

            return AIResult(
                ok=True, provider=self.name, model=model,
                content=self._parse_json(text) if schema else {},
                text=text,
                input_tokens=message.usage.input_tokens,
                output_tokens=message.usage.output_tokens,
            )

        except anthropic.APIStatusError as e:
            return self._failure(f'HTTP {e.status_code}: {e.message}', model)
        except anthropic.APIConnectionError:
            return self._failure('could not reach the Anthropic API', model)
        except Exception as e:
            return self._failure(f'{type(e).__name__}: {e}', model)


class OpenAIProvider(AIProvider):
    """Analysis via the OpenAI Chat Completions API."""

    name = 'openai'
    sdk_module = 'openai'
    install_hint = 'openai'
    default_model = 'gpt-4o'

    def credentials_available(self) -> bool:
        return bool(self.config.ai_api_key)

    async def analyze(self, system, prompt, schema=None) -> AIResult:
        import openai

        model = self.config.ai_model or self.default_model

        try:
            client = openai.AsyncOpenAI(
                api_key=self.config.ai_api_key,
                base_url=self.config.ai_base_url or None,
                timeout=self.config.ai_timeout,
                max_retries=2,
            )

            kwargs: dict[str, Any] = {
                'model': model,
                'max_tokens': self.config.ai_max_tokens,
                'messages': [
                    {'role': 'system', 'content': system},
                    {'role': 'user', 'content': prompt},
                ],
            }

            if schema:
                kwargs['response_format'] = {
                    'type': 'json_schema',
                    'json_schema': {
                        'name': 'triage',
                        'strict': True,
                        'schema': schema,
                    },
                }

            response = await client.chat.completions.create(**kwargs)
            text = response.choices[0].message.content or ''
            usage = response.usage

            return AIResult(
                ok=True, provider=self.name, model=model,
                content=self._parse_json(text) if schema else {},
                text=text,
                input_tokens=getattr(usage, 'prompt_tokens', 0) or 0,
                output_tokens=getattr(usage, 'completion_tokens', 0) or 0,
            )

        except Exception as e:
            return self._failure(f'{type(e).__name__}: {e}', model)


class GeminiProvider(AIProvider):
    """Analysis via the Google Gemini API."""

    name = 'gemini'
    sdk_module = 'google.genai'
    install_hint = 'gemini'
    default_model = 'gemini-2.0-flash'

    def credentials_available(self) -> bool:
        return bool(self.config.ai_api_key)

    async def analyze(self, system, prompt, schema=None) -> AIResult:
        from google import genai
        from google.genai import types

        model = self.config.ai_model or self.default_model

        try:
            client = genai.Client(api_key=self.config.ai_api_key)

            cfg: dict[str, Any] = {
                'system_instruction': system,
                'max_output_tokens': self.config.ai_max_tokens,
            }
            if schema:
                cfg['response_mime_type'] = 'application/json'
                cfg['response_schema'] = _to_gemini_schema(schema)

            response = await client.aio.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(**cfg),
            )

            text = response.text or ''
            usage = getattr(response, 'usage_metadata', None)

            return AIResult(
                ok=True, provider=self.name, model=model,
                content=self._parse_json(text) if schema else {},
                text=text,
                input_tokens=getattr(usage, 'prompt_token_count', 0) or 0,
                output_tokens=getattr(usage, 'candidates_token_count', 0) or 0,
            )

        except Exception as e:
            return self._failure(f'{type(e).__name__}: {e}', model)


class OllamaProvider(AIProvider):
    """
    Analysis via a local Ollama daemon.

    No SDK and no API key: this talks plain HTTP to a host the operator runs.
    It exists so that organisations who cannot send their monitored-domain list
    to a third party can still use AI triage, since that list reveals both what
    they own and what they are worried about.
    """

    name = 'ollama'
    sdk_module = None
    default_model = 'llama3.1'

    def credentials_available(self) -> bool:
        # A local daemon needs no credentials, only an address
        return bool(self.config.ai_base_url or True)

    async def analyze(self, system, prompt, schema=None) -> AIResult:
        import aiohttp

        model = self.config.ai_model or self.default_model
        base = (self.config.ai_base_url or 'http://localhost:11434').rstrip('/')

        payload: dict[str, Any] = {
            'model': model,
            'system': system,
            'prompt': prompt,
            'stream': False,
            'options': {'num_predict': self.config.ai_max_tokens},
        }
        if schema:
            # Ollama constrains output to a JSON schema when given one
            payload['format'] = schema

        try:
            timeout = aiohttp.ClientTimeout(total=self.config.ai_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(f'{base}/api/generate', json=payload) as resp:
                    if resp.status != 200:
                        body = (await resp.text())[:200]
                        return self._failure(f'HTTP {resp.status}: {body}', model)
                    data = await resp.json()

            text = data.get('response', '') or ''

            return AIResult(
                ok=True, provider=self.name, model=model,
                content=self._parse_json(text) if schema else {},
                text=text,
                input_tokens=data.get('prompt_eval_count', 0) or 0,
                output_tokens=data.get('eval_count', 0) or 0,
            )

        except Exception as e:
            return self._failure(
                f'{type(e).__name__}: {e} (is Ollama running at {base}?)', model
            )


def _to_gemini_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """
    Adapt a JSON schema to what the Gemini API accepts.

    Gemini rejects ``additionalProperties``, which the other providers require
    for strict mode, so it is stripped recursively rather than maintaining two
    copies of the schema.

    Args:
        schema: JSON schema

    Returns:
        A copy without unsupported keys
    """
    if not isinstance(schema, dict):
        return schema

    out = {}
    for key, value in schema.items():
        if key == 'additionalProperties':
            continue
        if isinstance(value, dict):
            out[key] = _to_gemini_schema(value)
        elif isinstance(value, list):
            out[key] = [_to_gemini_schema(v) for v in value]
        else:
            out[key] = value
    return out


PROVIDERS: dict[str, type[AIProvider]] = {
    'claude': ClaudeProvider,
    'openai': OpenAIProvider,
    'gemini': GeminiProvider,
    'ollama': OllamaProvider,
}


def get_provider(config) -> AIProvider | None:
    """
    Build the configured provider.

    Args:
        config: Configuration object

    Returns:
        A provider instance, or None when the name is unknown
    """
    provider_cls = PROVIDERS.get((config.ai_provider or '').lower())
    return provider_cls(config) if provider_cls else None

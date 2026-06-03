"""
scripts/thioclaw_agent/providers.py
-----------------------------------
LLM provider boilerplate for the ThIOClaw control plane (raw LiteLLM loop).

Resolves a THIOCLAW_PROVIDER alias (or infers one from THIOCLAW_MODEL)
into the kwargs litellm.completion() needs. Adding a new provider is a
matter of writing one function and registering it in PROVIDER_PROFILES.

Supported (via LiteLLM):
  - ollama          local-first default
  - anthropic       direct ANTHROPIC_API_KEY
  - openai          direct OPENAI_API_KEY
  - bedrock         AWS Bedrock via boto3 default credential chain
  - vertex_ai       Google Vertex AI (Claude on Vertex or Gemini)

Required env vars for each provider are documented inline below.

--------------------------------------------------------------------------
Backwards compatibility (one release):
  Legacy OPENCLAW_PROVIDER, OPENCLAW_MODEL, OPENCLAW_BASE_URL env vars are
  still honored when the THIOCLAW_* equivalent is unset, with a deprecation
  warning printed once per process. They will be removed in the next release.
--------------------------------------------------------------------------
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional


_LEGACY_WARNED: set[str] = set()


def _env(var: str, default: Optional[str] = None) -> Optional[str]:
    """Read THIOCLAW_<NAME> with fallback to legacy OPENCLAW_<NAME>.

    One-shot deprecation warning per legacy variable; the new name always wins.
    """
    val = os.getenv(var)
    if val is not None:
        return val

    if var.startswith("THIOCLAW_"):
        legacy = "OPENCLAW_" + var[len("THIOCLAW_"):]
        legacy_val = os.getenv(legacy)
        if legacy_val is not None:
            if legacy not in _LEGACY_WARNED:
                print(
                    f"[ThIOClaw] DEPRECATED: env var {legacy} is deprecated; "
                    f"use {var}. Falling back for this release.",
                    file=sys.stderr,
                )
                _LEGACY_WARNED.add(legacy)
            return legacy_val

    return default


@dataclass(frozen=True)
class ProviderResolution:
    """Resolved provider config ready to pass to litellm.completion()."""
    provider: str
    model: str
    base_url: Optional[str] = None
    extra_kwargs: dict = field(default_factory=dict)
    required_env: tuple = ()

    def summary(self) -> str:
        return f"{self.provider}::{self.model}" + (
            f" via {self.base_url}" if self.base_url else ""
        )


# ---------------------------------------------------------------------------
# Provider profiles
# ---------------------------------------------------------------------------

def _ollama() -> ProviderResolution:
    """Local Ollama. Default model: llama3.1:8b."""
    return ProviderResolution(
        provider="ollama",
        model=_env("THIOCLAW_MODEL", "ollama/llama3.1:8b"),
        base_url=_env("THIOCLAW_BASE_URL", "http://localhost:11434"),
    )


def _anthropic() -> ProviderResolution:
    """Direct Anthropic API. Required: ANTHROPIC_API_KEY."""
    return ProviderResolution(
        provider="anthropic",
        model=_env("THIOCLAW_MODEL", "claude-3-5-sonnet-20241022"),
        required_env=("ANTHROPIC_API_KEY",),
    )


def _openai() -> ProviderResolution:
    """Direct OpenAI API. Required: OPENAI_API_KEY."""
    return ProviderResolution(
        provider="openai",
        model=_env("THIOCLAW_MODEL", "gpt-4o"),
        required_env=("OPENAI_API_KEY",),
    )


def _bedrock() -> ProviderResolution:
    """
    AWS Bedrock via LiteLLM.

    Auth uses the boto3 default credential chain:
      - env vars: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
      - or: ~/.aws/credentials profile via AWS_PROFILE
      - or: IAM role (EC2/ECS/EKS)
    Required: AWS_REGION_NAME (defaults to us-east-1 if unset).

    Example model strings:
      bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0
      bedrock/anthropic.claude-3-haiku-20240307-v1:0
      bedrock/meta.llama3-70b-instruct-v1:0
    """
    return ProviderResolution(
        provider="bedrock",
        model=_env(
            "THIOCLAW_MODEL",
            "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0",
        ),
        extra_kwargs={
            "aws_region_name": os.getenv("AWS_REGION_NAME", "us-east-1"),
        },
        required_env=("AWS_REGION_NAME",),
    )


def _vertex_ai() -> ProviderResolution:
    """
    Google Vertex AI via LiteLLM. Supports both Anthropic Claude on Vertex
    and Google's own Gemini models.

    Required env:
      VERTEXAI_PROJECT                 GCP project id
      VERTEXAI_LOCATION                e.g. us-central1, us-east5
      GOOGLE_APPLICATION_CREDENTIALS   path to a service-account JSON key

    Example model strings:
      vertex_ai/gemini-1.5-pro
      vertex_ai/gemini-1.5-flash
      vertex_ai/claude-3-5-sonnet@20240620
    """
    return ProviderResolution(
        provider="vertex_ai",
        model=_env("THIOCLAW_MODEL", "vertex_ai/gemini-1.5-pro"),
        extra_kwargs={
            "vertex_project": os.getenv("VERTEXAI_PROJECT"),
            "vertex_location": os.getenv("VERTEXAI_LOCATION", "us-central1"),
        },
        required_env=(
            "VERTEXAI_PROJECT",
            "VERTEXAI_LOCATION",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ),
    )


PROVIDER_PROFILES: dict[str, Callable[[], ProviderResolution]] = {
    "ollama": _ollama,
    "anthropic": _anthropic,
    "openai": _openai,
    "bedrock": _bedrock,
    "vertex_ai": _vertex_ai,
}


# ---------------------------------------------------------------------------
# Resolution + diagnostics
# ---------------------------------------------------------------------------

def _infer_provider_from_model(model: str) -> Optional[str]:
    """Best-effort inference from a model prefix when no alias is set."""
    if not model:
        return None
    if model.startswith("bedrock/"):
        return "bedrock"
    if model.startswith("vertex_ai/"):
        return "vertex_ai"
    if model.startswith("ollama/"):
        return "ollama"
    if model.startswith(("openai/", "gpt-")):
        return "openai"
    if model.startswith(("anthropic/", "claude-")):
        return "anthropic"
    return None


def resolve_provider(provider: Optional[str] = None) -> ProviderResolution:
    """
    Order of precedence:
      1. explicit `provider` argument
      2. THIOCLAW_PROVIDER env var (or legacy OPENCLAW_PROVIDER with warning)
      3. inferred from THIOCLAW_MODEL prefix
      4. default: 'ollama'
    """
    alias = provider or _env("THIOCLAW_PROVIDER")
    if not alias:
        alias = _infer_provider_from_model(_env("THIOCLAW_MODEL", "")) or "ollama"

    if alias not in PROVIDER_PROFILES:
        raise ValueError(
            f"Unknown THIOCLAW_PROVIDER '{alias}'. "
            f"Known: {sorted(PROVIDER_PROFILES)}"
        )
    return PROVIDER_PROFILES[alias]()


def check_required_env(resolution: ProviderResolution) -> list[str]:
    """Return required env vars that are missing. Informational only —
    we don't fail-fast because LiteLLM may pick up creds from other sources
    (boto3 chain, gcloud ADC, etc.)."""
    return [var for var in resolution.required_env if not os.getenv(var)]


def completion_kwargs(resolution: ProviderResolution) -> dict:
    """Build the kwargs dict for litellm.completion() from a resolution.
    Filters out None values so LiteLLM falls back to its own defaults."""
    kwargs: dict = {"model": resolution.model}
    if resolution.base_url:
        kwargs["base_url"] = resolution.base_url
    for k, v in resolution.extra_kwargs.items():
        if v is not None:
            kwargs[k] = v
    return kwargs

"""
LLM client factory for LogonTracer AI analysis.
"""
import logging

from .llm_config import LLMConfig
from .openai_client import OpenAIClient
from .ollama_client import OllamaClient

logger = logging.getLogger(__name__)


def create_llm_client(config: LLMConfig):
    """Create a provider-specific LLM client."""
    provider = (config.provider or "openai").lower()

    if provider == "openai":
        return OpenAIClient(config)
    if provider == "ollama":
        return OllamaClient(config)

    logger.warning(f"Unsupported LLM provider: {config.provider}")
    return None

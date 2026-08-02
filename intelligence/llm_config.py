"""
LLM Configuration for LogonTracer AI Analysis
"""
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMConfig:
    provider: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    max_completion_tokens: Optional[int] = None
    final_report_max_completion_tokens: Optional[int] = None
    timeout: Optional[int] = None
    agent_max_iterations: Optional[int] = None
    response_language: Optional[str] = None
    context_length: Optional[int] = None
    keep_alive: Optional[str] = None


def get_llm_config() -> LLMConfig:
    """Load LLM configuration from database with safe session handling"""
    offline_mode = os.environ.get('LOGONTRACER_OFFLINE', '').strip().lower() in {'1', 'true', 'yes', 'on'}
    default_provider = os.environ.get('LOGONTRACER_LLM_PROVIDER', 'openai').strip().lower()
    if offline_mode:
        default_provider = 'ollama'
    default_ollama_base_url = os.environ.get('OLLAMA_BASE_URL', 'http://ollama:11434/v1')
    default_ollama_model = os.environ.get('OLLAMA_MODEL', 'gpt-oss:20b')
    default_context_length = _safe_int(os.environ.get('OLLAMA_CONTEXT_LENGTH'), 16384)
    default_keep_alive = os.environ.get('OLLAMA_KEEP_ALIVE', '30m')
    default_temperature = _safe_float(os.environ.get('LOGONTRACER_TEMPERATURE'), 0)
    default_max_completion_tokens = _safe_int(os.environ.get('LOGONTRACER_MAX_COMPLETION_TOKENS'), 4096)
    default_final_report_max_completion_tokens = _safe_int(
        os.environ.get('LOGONTRACER_FINAL_REPORT_MAX_COMPLETION_TOKENS'),
        max(default_max_completion_tokens, 4096)
    )
    default_agent_max_iterations = _safe_int(os.environ.get('LOGONTRACER_AGENT_MAX_ITERATIONS'), 10)
    
    fallback_config = LLMConfig(
        provider=default_provider,
        api_key=os.environ.get('OPENAI_API_KEY') if default_provider == 'openai' else None,
        base_url=default_ollama_base_url if default_provider == 'ollama' else None,
        model=default_ollama_model if default_provider == 'ollama' else os.environ.get('OPENAI_MODEL', 'gpt-5-mini'),
        temperature=default_temperature,
        max_tokens=default_max_completion_tokens,
        max_completion_tokens=default_max_completion_tokens,
        final_report_max_completion_tokens=default_final_report_max_completion_tokens,
        timeout=300,
        agent_max_iterations=default_agent_max_iterations,
        response_language='en',
        context_length=default_context_length,
        keep_alive=default_keep_alive
    )
    
    try:
        db_setting = _safe_get_db_setting()
        
        if db_setting:
            provider = (getattr(db_setting, 'llm_provider', None) or 'openai').strip().lower()
            if offline_mode:
                provider = 'ollama'
            model = db_setting.openai_model
            api_key = db_setting.openai_api_key
            base_url = None
            if provider == 'ollama':
                model = getattr(db_setting, 'ollama_model', None) or default_ollama_model
                api_key = None
                base_url = getattr(db_setting, 'llm_base_url', None) or default_ollama_base_url

            if db_setting.ai_enabled:
                return LLMConfig(
                    provider=provider,
                    api_key=api_key,
                    base_url=base_url,
                    model=model,
                    temperature=db_setting.temperature if db_setting.temperature is not None else default_temperature,
                    max_tokens=db_setting.max_completion_tokens or default_max_completion_tokens,
                    max_completion_tokens=db_setting.max_completion_tokens or default_max_completion_tokens,
                    final_report_max_completion_tokens=default_final_report_max_completion_tokens,
                    timeout=300,
                    agent_max_iterations=getattr(db_setting, 'agent_max_iterations', None) or default_agent_max_iterations,
                    response_language=getattr(db_setting, 'response_language', 'en'),
                    context_length=getattr(db_setting, 'ollama_context_length', default_context_length),
                    keep_alive=getattr(db_setting, 'ollama_keep_alive', default_keep_alive)
                )
            else:
                return LLMConfig(
                    provider=provider,
                    api_key=None,
                    base_url=base_url,
                    model=model,
                    temperature=db_setting.temperature if db_setting.temperature is not None else default_temperature,
                    max_tokens=db_setting.max_completion_tokens or default_max_completion_tokens,
                    max_completion_tokens=db_setting.max_completion_tokens or default_max_completion_tokens,
                    final_report_max_completion_tokens=default_final_report_max_completion_tokens,
                    timeout=300,
                    agent_max_iterations=getattr(db_setting, 'agent_max_iterations', None) or default_agent_max_iterations,
                    response_language=getattr(db_setting, 'response_language', 'en'),
                    context_length=getattr(db_setting, 'ollama_context_length', default_context_length),
                    keep_alive=getattr(db_setting, 'ollama_keep_alive', default_keep_alive)
                )
        else:
            print("No AI settings found in database, using fallback config")
            
    except Exception as e:
        print(f"Failed to load LLM config from database: {e}")
        
    return fallback_config


def _safe_get_db_setting():
    """Safely get database setting with Flask context handling"""
    
    try:
        from flask import has_app_context, current_app
        
        if has_app_context() and current_app:
            try:
                from logontracer import db, AISetting
                
                result = AISetting.query.first()
                return result
                
            except Exception as e:
                print(f"Database access failed: {e}")
                return None
        else:
            print("No Flask context available")
            return None
            
    except ImportError as e:
        print(f"Import failed: {e}")
        return None
    except Exception as e:
        print(f"Context check failed: {e}")
        return None


def validate_config(config: LLMConfig) -> bool:
    """Validate LLM configuration"""
    if not config:
        return False
    if config.provider == 'openai' and not config.api_key:
        return False
    if config.provider == 'ollama' and (not config.base_url or not config.model):
        return False
    if config.provider not in {'openai', 'ollama'}:
        return False
    return True


def _safe_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

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
    model: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    max_completion_tokens: Optional[int] = None
    timeout: Optional[int] = None
    agent_max_iterations: Optional[int] = None
    response_language: Optional[str] = None


def get_llm_config() -> LLMConfig:
    """Load LLM configuration from database with safe session handling"""
    
    fallback_config = LLMConfig(
        provider='openai',
        api_key=None,
        model='gpt-5-mini',
        temperature=0,
        max_tokens=8000,
        max_completion_tokens=8000,
        timeout=300,
        agent_max_iterations=10,
        response_language='en'
    )
    
    try:
        db_setting = _safe_get_db_setting()
        
        if db_setting:
            if db_setting.ai_enabled:
                return LLMConfig(
                    provider='openai',
                    api_key=db_setting.openai_api_key,
                    model=db_setting.openai_model,
                    temperature=db_setting.temperature,
                    max_tokens=8000,
                    max_completion_tokens=db_setting.max_completion_tokens,
                    timeout=300,
                    agent_max_iterations=getattr(db_setting, 'agent_max_iterations', 10),
                    response_language=getattr(db_setting, 'response_language', 'en')
                )
            else:
                return LLMConfig(
                    provider='openai',
                    api_key=None,
                    model=db_setting.openai_model,
                    temperature=db_setting.temperature,
                    max_tokens=8000,
                    max_completion_tokens=db_setting.max_completion_tokens,
                    timeout=300,
                    agent_max_iterations=getattr(db_setting, 'agent_max_iterations', 10),
                    response_language=getattr(db_setting, 'response_language', 'en')
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
    return True

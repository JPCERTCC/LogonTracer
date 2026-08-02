"""
AI Analysis Engine for LogonTracer
"""
import logging
from typing import Dict, Any, List
from .llm_config import get_llm_config, validate_config
from .llm_client_factory import create_llm_client

logger = logging.getLogger(__name__)


class SecurityAnalysisEngine:
    def __init__(self):
        self.config = get_llm_config()
        self.is_enabled = validate_config(self.config)
        
        if self.is_enabled:
            self.client = create_llm_client(self.config)
            if self.client is None:
                self.is_enabled = False
        else:
            logger.warning("AI analysis disabled: Invalid configuration")
    
    async def analyze_query_results(self, query_type: str, analysis_data: Dict[str, Any], 
                                  graph_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security patterns from query results"""
        
        if not self.is_enabled:
            return self._create_disabled_response()
        
        try:
            enhanced_data = analysis_data
            
            # Perform AI analysis
            analysis_result = await self.client.analyze_security_pattern(query_type, enhanced_data)
            
            # Add metadata
            analysis_result['analysis_metadata'] = {
                'query_type': query_type,
                'ai_provider': self.config.provider,
                'model': self.config.model,
                'timestamp': self._get_timestamp()
            }
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            return self._create_error_response(str(e))
    
    def _calculate_graph_density(self, stats: Dict[str, Any]) -> float:
        """Calculate graph density metric"""
        nodes = stats.get('node_count', 0)
        edges = stats.get('edge_count', 0)
        
        if nodes <= 1:
            return 0.0
        
        max_edges = nodes * (nodes - 1)
        return (edges / max_edges) if max_edges > 0 else 0.0
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
    
    def _create_disabled_response(self) -> Dict[str, Any]:
        """Create response when AI analysis is disabled"""
        return {
            "risk_level": "Unknown",
            "summary": "AI analysis is currently disabled. Check configuration.",
            "key_findings": ["AI analysis requires a valid LLM provider configuration"],
            "security_concerns": ["Unable to perform automated AI analysis"],
            "mitre_tactics": [],
            "recommendations": ["Configure OpenAI or Ollama settings to enable AI analysis"]
        }
    
    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create error response"""
        return {
            "risk_level": "Unknown",
            "summary": f"Analysis failed: {error_message}",
            "key_findings": ["Analysis could not be completed due to error"],
            "security_concerns": ["Unable to assess security risks automatically"],
            "mitre_tactics": [],
            "recommendations": ["Check system logs and try again"]
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get analysis engine status"""
        return {
            "enabled": self.is_enabled,
            "provider": self.config.provider if self.is_enabled else None,
            "model": self.config.model if self.is_enabled else None,
            "api_key_configured": bool(self.config.api_key) if self.is_enabled else False,
            "base_url": self.config.base_url if self.is_enabled and self.config.provider == "ollama" else None
        }

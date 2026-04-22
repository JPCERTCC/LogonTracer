"""
LLM Agent Engine for Autonomous Threat Detection
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from neo4j import GraphDatabase
from neo4j.graph import Node, Relationship, Path
from .llm_config import get_llm_config, validate_config
from .openai_client import OpenAIClient

logger = logging.getLogger(__name__)


class LLMDetectionAgent:
    """LLM-powered autonomous threat detection agent"""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, database: str = "neo4j"):
        self.config = get_llm_config()
        self.is_enabled = validate_config(self.config)
        
        if self.is_enabled:
            self.llm = OpenAIClient(self.config)
        else:
            self.llm = None
            
        # Neo4j connection details
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.database = database
        
        # Investigation state
        self.investigation_history = []
        self.discovered_threats = []
        self.max_iterations = self.config.agent_max_iterations
    
    async def run_autonomous_detection(self, initial_context: str = None) -> Dict[str, Any]:
        """Run autonomous threat detection cycle"""
        if not self.is_enabled:
            return self._create_disabled_response()
            
        logger.info("Starting autonomous threat detection...")
        
        # Start AI session for this agent run with unique timestamp-based ID
        session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]  # Include milliseconds
        session_id = f"agent_autonomous_detection_{session_timestamp}"
        self.llm.start_session(session_id)
        
        # Initialize investigation
        investigation_context = initial_context or "Detect suspicious logon behavior in Active Directory"
        
        try:
            # Run iterative detection cycle
            for iteration in range(self.max_iterations):
                logger.info(f"Detection iteration {iteration + 1}/{self.max_iterations}")
                
                # Step 1: Generate investigation query (with retry logic for errors and empty responses)
                query_response = await self._generate_investigation_query_with_retry(investigation_context, iteration)
                
                # Check if we got a valid response
                if not query_response or not self._is_valid_query_response(query_response):
                    logger.warning(f"Failed to generate valid query in iteration {iteration + 1}, stopping investigation")
                    break
                    
                cypher_query = query_response['cypher_query']
                investigation_focus = query_response.get('investigation_focus', 'General analysis')
                
                # Step 2: Execute query against Neo4j
                query_results, query_error = await self._execute_neo4j_query_with_error_handling(cypher_query)
                if query_error:
                    # Query failed, record the error and continue to next iteration
                    error_step = {
                        'iteration': iteration + 1,
                        'query': cypher_query,
                        'focus': investigation_focus,
                        'error': query_error,
                        'results_count': 0,
                        'analysis': {
                            'error': True,
                            'error_message': query_error,
                            'threat_detected': False
                        }
                    }
                    self.investigation_history.append(error_step)
                    continue
                    
                if not query_results:
                    logger.info(f"No results returned for iteration {iteration + 1}")
                    # Record empty result step
                    empty_step = {
                        'iteration': iteration + 1,
                        'query': cypher_query,
                        'focus': investigation_focus,
                        'results_count': 0,
                        'analysis': {
                            'threat_detected': False,
                            'investigation_complete': False,
                            'no_results': True
                        }
                    }
                    self.investigation_history.append(empty_step)
                    continue
                    
                # Step 3: Analyze results with LLM
                analysis_response = await self._analyze_query_results(
                    cypher_query, query_results, investigation_focus, iteration
                )
                
                # Step 4: Record investigation step
                investigation_step = {
                    'iteration': iteration + 1,
                    'query': cypher_query,
                    'focus': investigation_focus,
                    'results_count': len(query_results),
                    'analysis': analysis_response
                }
                self.investigation_history.append(investigation_step)
                
                # Step 5: Check if threats were discovered
                if analysis_response.get('threat_detected'):
                    threat_info = {
                        'iteration': iteration + 1,
                        'threat_type': analysis_response.get('threat_type'),
                        'severity': analysis_response.get('severity'),
                        'description': analysis_response.get('threat_description'),
                        'evidence': analysis_response.get('evidence'),
                        'query': cypher_query,
                        'results': query_results[:100]  # Limit results for storage
                    }
                    self.discovered_threats.append(threat_info)
                
                # Step 6: Determine next investigation step
                if analysis_response.get('investigation_complete'):
                    logger.info("Investigation marked as complete by LLM")
                    break
                    
                investigation_context = analysis_response.get('next_investigation_context', investigation_context)
                
                # Rate limiting
                await asyncio.sleep(1)
                
            # Generate final report
            final_report = await self._generate_final_report()
            
            # End AI session with complete results
            complete_session_report = {
                'session_type': 'agent_autonomous_detection',
                'investigation_context': initial_context,
                'iterations_run': len(self.investigation_history),
                'threats_discovered': len(self.discovered_threats),
                'investigation_history': self.investigation_history,
                'discovered_threats': self.discovered_threats,
                'final_report': final_report
            }
            self.llm.end_session(final_report=complete_session_report)
            
            return {
                'success': True,
                'investigation_completed': True,
                'iterations_run': len(self.investigation_history),
                'threats_discovered': len(self.discovered_threats),
                'investigation_history': self.investigation_history,
                'discovered_threats': self.discovered_threats,
                'final_report': final_report
            }
            
        except Exception as e:
            logger.error(f"Autonomous detection failed: {str(e)}")
            
            # End session with error information
            error_session_report = {
                'session_type': 'agent_autonomous_detection',
                'error': str(e),
                'investigation_context': initial_context,
                'iterations_run': len(self.investigation_history),
                'threats_discovered': len(self.discovered_threats),
                'investigation_history': self.investigation_history,
                'discovered_threats': self.discovered_threats
            }
            self.llm.end_session(final_report=error_session_report)
            
            return {
                'success': False,
                'error': str(e),
                'investigation_history': self.investigation_history,
                'discovered_threats': self.discovered_threats
            }
    
    async def _generate_investigation_query(self, context: str) -> Dict[str, Any]:
        """Generate Cypher query for investigation using LLM"""
        try:
            query_data = {
                'investigation_context': context,
                'previous_queries': [step['query'] for step in self.investigation_history],
                'discovered_threats': self.discovered_threats
            }
            
            return await self.llm.analyze_security_pattern("agent_query_generation", query_data)
        except Exception as e:
            logger.error(f"Failed to generate investigation query: {str(e)}")
            return {}
    
    async def _execute_neo4j_query_with_error_handling(self, cypher_query: str) -> tuple[List[Dict[str, Any]], Optional[str]]:
        """Execute Cypher query against Neo4j with error handling"""
        try:
            # Execute query with limits for safety
            safe_query = self._add_safety_limits(cypher_query)
            logger.info(f"Executing query: {safe_query}")
            records = []

            with GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password)
            ) as driver:
                with driver.session(database=self.database) as neo4j_session:
                    result = neo4j_session.run(safe_query)
                    for record in result:
                        record_dict = {}
                        for key in record.keys():
                            record_dict[key] = self._serialize_neo4j_value(record[key])
                        records.append(record_dict)
            
            logger.info(f"Query returned {len(records)} records")
            return records, None
            
        except Exception as e:
            error_message = f"Cypher query execution failed: {str(e)}"
            logger.error(error_message)
            return [], error_message

    def _serialize_neo4j_value(self, value: Any) -> Any:
        """Convert official Neo4j driver values into JSON-safe Python types."""
        if isinstance(value, Node):
            node_data = dict(value.items())
            node_data["_labels"] = list(value.labels)
            node_data["_element_id"] = value.element_id
            return node_data

        if isinstance(value, Relationship):
            rel_data = dict(value.items())
            rel_data["_type"] = value.type
            rel_data["_element_id"] = value.element_id
            return rel_data

        if isinstance(value, Path):
            return {
                "nodes": [self._serialize_neo4j_value(node) for node in value.nodes],
                "relationships": [self._serialize_neo4j_value(rel) for rel in value.relationships],
            }

        if isinstance(value, list):
            return [self._serialize_neo4j_value(item) for item in value]

        if isinstance(value, dict):
            return {key: self._serialize_neo4j_value(item) for key, item in value.items()}

        return value
    
    def _add_safety_limits(self, cypher_query: str) -> str:
        """Add safety limits to Cypher query"""
        query = cypher_query.strip()
        
        # Add LIMIT if not present
        if 'LIMIT' not in query.upper():
            query += ' LIMIT 1000'
        
        return query
    
    async def _analyze_query_results(self, query: str, results: List[Dict], focus: str, iteration: int) -> Dict[str, Any]:
        """Analyze query results using LLM"""
        try:
            analysis_data = {
                'cypher_query': query,
                'investigation_focus': focus,
                'results': results,
                'results_count': len(results),
                'previous_findings': self.discovered_threats,
                'iteration': iteration,
                'max_iterations': self.max_iterations
            }
            
            return await self.llm.analyze_security_pattern("agent_result_analysis", analysis_data)
        except Exception as e:
            logger.error(f"Failed to analyze query results: {str(e)}")
            return {
                'threat_detected': False,
                'error': str(e),
                'investigation_complete': False
            }
    
    async def _generate_final_report(self) -> Dict[str, Any]:
        """Generate final investigation report"""
        try:
            report_data = {
                'investigation_history': self.investigation_history,
                'discovered_threats': self.discovered_threats,
                'investigation_summary': {
                    'total_iterations': len(self.investigation_history),
                    'threats_found': len(self.discovered_threats)
                }
            }
            
            return await self.llm.analyze_security_pattern("agent_final_report", report_data)
        except Exception as e:
            logger.error(f"Failed to generate final report: {str(e)}")
            return {
                'executive_summary': 'Failed to generate comprehensive report',
                'overall_risk_level': 'unknown',
                'error': str(e)
            }
    
    def _create_disabled_response(self) -> Dict[str, Any]:
        """Create response when agent is disabled"""
        return {
            'success': False,
            'error': 'LLM Agent is disabled. Check AI configuration.',
            'investigation_completed': False,
            'threats_discovered': 0,
            'investigation_history': [],
            'discovered_threats': []
        }
    
    async def _generate_investigation_query_with_retry(self, context: str, iteration: int) -> Dict[str, Any]:
        """Generate Cypher query with retry logic for errors and empty responses"""
        max_retries = 3
        
        for retry_attempt in range(max_retries):
            try:
                # Get recent errors to inform the LLM
                recent_errors = self._get_recent_query_errors()
                
                query_data = {
                    'investigation_context': context,
                    'previous_queries': [step['query'] for step in self.investigation_history],
                    'discovered_threats': self.discovered_threats,
                    'recent_errors': recent_errors,
                    'retry_attempt': retry_attempt,
                    'iteration': iteration
                }
                
                if recent_errors:
                    logger.info(f"Generating query with error feedback (attempt {retry_attempt + 1})")
                    response = await self.llm.analyze_security_pattern("agent_query_generation_with_errors", query_data)
                else:
                    response = await self.llm.analyze_security_pattern("agent_query_generation", query_data)
                
                # Check if response is valid and contains required data
                if self._is_valid_query_response(response):
                    return response
                else:
                    logger.warning(f"Invalid or empty response received (attempt {retry_attempt + 1}): {response}")
                    # Add this attempt as an "error" for the next retry
                    if retry_attempt < max_retries - 1:
                        self._add_empty_response_error(response, retry_attempt)
                        
            except Exception as e:
                logger.error(f"Failed to generate investigation query (attempt {retry_attempt + 1}): {str(e)}")
                if retry_attempt < max_retries - 1:
                    self._add_generation_error(str(e), retry_attempt)
            
            # Wait before retry
            if retry_attempt < max_retries - 1:
                await asyncio.sleep(1)
        
        logger.error("Failed to generate valid query after all retry attempts")
        return {}
    
    def _is_valid_query_response(self, response: Dict[str, Any]) -> bool:
        """Check if query response is valid and usable"""
        if not response:
            return False
        
        cypher_query = response.get('cypher_query', '').strip()
        if not cypher_query:
            return False
        
        # Basic Cypher query validation
        if not any(keyword in cypher_query.upper() for keyword in ['MATCH', 'RETURN', 'WITH']):
            return False
        
        return True

    def _add_empty_response_error(self, response: Dict[str, Any], retry_attempt: int):
        """Add empty response as an error for feedback to LLM"""
        error_step = {
            'iteration': f"retry_{retry_attempt}",
            'query': '',
            'focus': 'Query Generation',
            'error': f'Empty or invalid response from LLM: {response}',
            'results_count': 0,
            'analysis': {
                'error': True,
                'error_message': 'LLM failed to generate valid Cypher query',
                'threat_detected': False
            }
        }
        self.investigation_history.append(error_step)

    def _add_generation_error(self, error_message: str, retry_attempt: int):
        """Add query generation error for feedback to LLM"""
        error_step = {
            'iteration': f"retry_{retry_attempt}",
            'query': '',
            'focus': 'Query Generation',
            'error': error_message,
            'results_count': 0,
            'analysis': {
                'error': True,
                'error_message': f'Query generation failed: {error_message}',
                'threat_detected': False
            }
        }
        self.investigation_history.append(error_step)

    def _get_recent_query_errors(self) -> List[Dict[str, Any]]:
        """Get recent query errors from investigation history"""
        recent_errors = []
        
        # Look at last 5 steps for errors (including generation errors)
        for step in self.investigation_history[-5:]:
            analysis = step.get('analysis', {})
            if analysis.get('error') or step.get('error'):
                error_info = {
                    'query': step.get('query', ''),
                    'error_message': step.get('error') or analysis.get('error_message', ''),
                    'focus': step.get('focus', ''),
                    'iteration': step.get('iteration', ''),
                    'error_type': 'generation_error' if not step.get('query') else 'execution_error'
                }
                recent_errors.append(error_info)
        
        return recent_errors


class ThreatInvestigationResult:
    """Container for threat investigation results"""
    
    def __init__(self, success: bool, threats: List[Dict], history: List[Dict]):
        self.success = success
        self.threats = threats
        self.history = history
        self.threat_count = len(threats)
    
    def get_high_severity_threats(self) -> List[Dict]:
        """Get high and critical severity threats"""
        return [t for t in self.threats if t.get('severity') in ['high', 'critical']]
    
    def get_threat_types(self) -> List[str]:
        """Get unique threat types discovered"""
        return list(set(t.get('threat_type') for t in self.threats if t.get('threat_type')))

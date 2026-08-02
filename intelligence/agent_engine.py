"""
LLM Agent Engine for Autonomous Threat Detection
"""
import asyncio
import logging
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from neo4j import GraphDatabase
from neo4j.graph import Node, Relationship, Path
from .llm_config import get_llm_config, validate_config
from .llm_client_factory import create_llm_client

logger = logging.getLogger(__name__)

MAX_AGENT_CYPHER_CHARS = 4000
MAX_AGENT_QUERY_RESULTS = 1000
ALLOWED_CYPHER_LABELS = {"Username", "IPAddress", "Domain", "Date", "Deletetime"}
ALLOWED_CYPHER_REL_TYPES = {"Event", "Group"}
ALLOWED_CYPHER_PROPERTIES = {
    "Username": {"user", "rights", "status", "rank", "sid", "counts", "counts4624", "counts4625", "counts4768", "counts4769", "counts4776", "detect"},
    "IPAddress": {"IP", "hostname", "rank"},
    "Domain": {"domain"},
    "Date": {"date", "start", "end"},
    "Deletetime": {"date", "domain", "user"},
    "Event": {"id", "logintype", "authname", "status", "count", "date", "servicename", "ticketencryptiontype"},
    "Group": set(),
}
DEFAULT_HITL_FOLLOWUP_CONTEXT = (
    "Continue with a different investigation target that is distinct from all previous queries "
    "and broadens coverage."
)


class LLMDetectionAgent:
    """LLM-powered autonomous threat detection agent"""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, database: str = "neo4j"):
        self.config = get_llm_config()
        self.is_enabled = validate_config(self.config)
        
        if self.is_enabled:
            self.llm = create_llm_client(self.config)
            self.is_enabled = self.llm is not None
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
        self.generation_errors = []
        self.analysis_errors = []
        self.max_iterations = self.config.agent_max_iterations
    
    async def run_autonomous_detection(
        self,
        initial_context: str = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
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
                    
                cypher_query = self._prepare_cypher_query_for_execution(query_response['cypher_query'])
                query_response['cypher_query'] = cypher_query
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
                    self._notify_progress(progress_callback)
                    continue
                    
                if not query_results:
                    logger.info(f"No results returned for iteration {iteration + 1}")
                    # Record empty result step
                    empty_step = {
                        'iteration': iteration + 1,
                        'query': cypher_query,
                        'focus': investigation_focus,
                        'results_count': 0,
                        'analysis': self._create_no_results_analysis(investigation_context)
                    }
                    self.investigation_history.append(empty_step)
                    self._notify_progress(progress_callback)
                    continue
                    
                # Step 3: Analyze results with LLM
                analysis_response = await self._analyze_query_results_with_retry(
                    cypher_query,
                    query_results,
                    investigation_focus,
                    iteration,
                    investigation_context=investigation_context
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

                self._notify_progress(progress_callback)
                
                # Step 6: Determine next investigation step
                if analysis_response.get('investigation_complete'):
                    logger.info("Investigation marked as complete by LLM")
                    break
                    
                investigation_context = analysis_response.get('next_investigation_context', investigation_context)
                
                # Rate limiting
                await asyncio.sleep(1)
                
            self._notify_progress(progress_callback, status='finalizing')

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
                'llm_generation_errors': self.generation_errors,
                'llm_analysis_errors': self.analysis_errors,
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
                'discovered_threats': self.discovered_threats,
                'llm_generation_errors': self.generation_errors,
                'llm_analysis_errors': self.analysis_errors
            }
            self.llm.end_session(final_report=error_session_report)
            
            return {
                'success': False,
                'error': str(e),
                'investigation_history': self.investigation_history,
                'discovered_threats': self.discovered_threats
            }

    def _notify_progress(
        self,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]],
        status: str = 'running'
    ) -> None:
        """Publish a snapshot after each completed autonomous investigation step."""
        if not progress_callback:
            return

        try:
            progress_callback({
                'status': status,
                'iterations_run': len(self.investigation_history),
                'max_iterations': self.max_iterations,
                'threats_discovered': len(self.discovered_threats),
                'investigation_history': list(self.investigation_history),
                'discovered_threats': list(self.discovered_threats)
            })
        except Exception as e:
            logger.warning(f"Failed to publish autonomous detection progress: {str(e)}")
    
    async def run_detection_step(
        self,
        investigation_context: str,
        iteration: int = 0,
        analyst_feedback: Optional[List[Dict[str, Any]]] = None,
        current_analyst_feedback: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Run a single analyst-guided investigation step."""
        if not self.is_enabled:
            return self._create_disabled_response()

        analyst_feedback = analyst_feedback or []
        current_analyst_feedback = current_analyst_feedback or []
        logger.info(f"Starting analyst-in-the-loop detection step {iteration + 1}")

        session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        self.llm.start_session(f"agent_hitl_step_{session_timestamp}")

        try:
            require_direct_cypher = self._requires_direct_cypher_execution(
                investigation_context,
                current_analyst_feedback
            )
            try:
                direct_cypher_query = self._extract_direct_cypher_from_context(
                    investigation_context,
                    strict=require_direct_cypher
                )
            except ValueError as e:
                logger.warning(f"Rejected analyst-approved HITL Cypher without regeneration: {str(e)}")
                investigation_step = self._create_rejected_direct_cypher_step(
                    investigation_context,
                    iteration,
                    str(e)
                )
                self.investigation_history.append(investigation_step)
                await self._attach_next_query_proposal(
                    investigation_step,
                    DEFAULT_HITL_FOLLOWUP_CONTEXT,
                    iteration + 1,
                    analyst_feedback
                )
                analysis = investigation_step.get('analysis', {})
                result = {
                    'success': True,
                    'analyst_in_loop': True,
                    'step': investigation_step,
                    'iteration': iteration + 1,
                    'next_iteration': len(self.investigation_history),
                    'max_iterations': self.max_iterations,
                    'investigation_complete': False,
                    'next_investigation_context': analysis.get('next_investigation_context', DEFAULT_HITL_FOLLOWUP_CONTEXT),
                    'investigation_history': self.investigation_history,
                    'discovered_threats': self.discovered_threats,
                    'threats_discovered': len(self.discovered_threats),
                    'analyst_feedback': analyst_feedback
                }
                self.llm.end_session(final_report=result)
                return result

            if direct_cypher_query:
                logger.info("Executing analyst-approved HITL Cypher without regenerating it")
                query_response = {
                    'cypher_query': direct_cypher_query,
                    'investigation_focus': 'Analyst-approved next step',
                    'expected_findings': 'Execute the Cypher query approved or supplied by the analyst.',
                    'threat_indicators': [],
                    'source': 'hitl_direct_cypher',
                    'requested_context': investigation_context
                }
            else:
                query_response = await self._generate_investigation_query_with_retry(
                    investigation_context,
                    iteration,
                    analyst_feedback,
                    current_analyst_feedback
                )

            if not query_response or not self._is_valid_query_response(query_response):
                result = {
                    'success': False,
                    'error': 'Failed to generate a valid investigation query',
                    'investigation_history': self.investigation_history,
                    'discovered_threats': self.discovered_threats,
                    'analyst_feedback': analyst_feedback,
                    'max_iterations': self.max_iterations
                }
                self.llm.end_session(final_report=result)
                return result

            cypher_query = self._prepare_cypher_query_for_execution(query_response['cypher_query'])
            query_response['cypher_query'] = cypher_query
            investigation_focus = query_response.get('investigation_focus', 'General analysis')

            query_results, query_error = await self._execute_neo4j_query_with_error_handling(cypher_query)
            if query_error:
                investigation_step = {
                    'iteration': iteration + 1,
                    'query': cypher_query,
                    'focus': investigation_focus,
                    'query_generation': query_response,
                    'error': query_error,
                    'results_count': 0,
                    'analysis': {
                        'error': True,
                        'error_message': query_error,
                        'threat_detected': False,
                        'investigation_complete': False,
                        'next_investigation_context': DEFAULT_HITL_FOLLOWUP_CONTEXT
                    }
                }
                self.investigation_history.append(investigation_step)
                await self._attach_next_query_proposal(
                    investigation_step,
                    DEFAULT_HITL_FOLLOWUP_CONTEXT,
                    iteration + 1,
                    analyst_feedback
                )
            elif not query_results:
                analysis_response = self._create_no_results_analysis()

                investigation_step = {
                    'iteration': iteration + 1,
                    'query': cypher_query,
                    'focus': investigation_focus,
                    'query_generation': query_response,
                    'results_count': 0,
                    'analysis': analysis_response
                }
                self.investigation_history.append(investigation_step)
                await self._attach_next_query_proposal(
                    investigation_step,
                    DEFAULT_HITL_FOLLOWUP_CONTEXT,
                    iteration + 1,
                    analyst_feedback
                )
            else:
                analysis_response = await self._analyze_query_results_with_retry(
                    cypher_query,
                    query_results,
                    investigation_focus,
                    iteration,
                    self._feedback_history_without_stale_next_step_instructions(analyst_feedback),
                    investigation_context
                )

                investigation_step = {
                    'iteration': iteration + 1,
                    'query': cypher_query,
                    'focus': investigation_focus,
                    'query_generation': query_response,
                    'results_count': len(query_results),
                    'analysis': analysis_response
                }
                self.investigation_history.append(investigation_step)

                if analysis_response.get('threat_detected'):
                    threat_info = {
                        'iteration': iteration + 1,
                        'threat_type': analysis_response.get('threat_type'),
                        'severity': analysis_response.get('severity'),
                        'description': analysis_response.get('threat_description'),
                        'evidence': analysis_response.get('evidence'),
                        'query': cypher_query,
                        'results': query_results[:100]
                    }
                    self.discovered_threats.append(threat_info)

            analysis = investigation_step.get('analysis', {})
            result = {
                'success': True,
                'analyst_in_loop': True,
                'step': investigation_step,
                'iteration': iteration + 1,
                'next_iteration': len(self.investigation_history),
                'max_iterations': self.max_iterations,
                'investigation_complete': bool(analysis.get('investigation_complete')),
                'next_investigation_context': analysis.get('next_investigation_context', investigation_context),
                'investigation_history': self.investigation_history,
                'discovered_threats': self.discovered_threats,
                'threats_discovered': len(self.discovered_threats),
                'analyst_feedback': analyst_feedback
            }
            self.llm.end_session(final_report=result)
            return result

        except Exception as e:
            logger.error(f"Analyst-in-the-loop detection step failed: {str(e)}")
            result = {
                'success': False,
                'error': str(e),
                'analyst_in_loop': True,
                'investigation_history': self.investigation_history,
                'discovered_threats': self.discovered_threats,
                'analyst_feedback': analyst_feedback
            }
            self.llm.end_session(final_report=result)
            return result

    async def generate_final_report_from_state(
        self,
        analyst_feedback: Optional[List[Dict[str, Any]]] = None,
        completion_reason: str = "analyst_requested_stop"
    ) -> Dict[str, Any]:
        """Generate a final report for an analyst-guided investigation."""
        if not self.is_enabled:
            return self._create_disabled_response()

        analyst_feedback = analyst_feedback or []
        session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        self.llm.start_session(f"agent_hitl_final_{session_timestamp}")

        final_report = await self._generate_final_report(analyst_feedback, completion_reason)
        result = {
            'success': True,
            'analyst_in_loop': True,
            'investigation_completed': True,
            'completion_reason': completion_reason,
            'iterations_run': len(self.investigation_history),
            'threats_discovered': len(self.discovered_threats),
            'investigation_history': self.investigation_history,
            'discovered_threats': self.discovered_threats,
            'analyst_feedback': analyst_feedback,
            'final_report': final_report
        }
        self.llm.end_session(final_report=result)
        return result

    async def _generate_investigation_query(
        self,
        context: str,
        analyst_feedback: Optional[List[Dict[str, Any]]] = None,
        current_analyst_feedback: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Generate Cypher query for investigation using LLM"""
        try:
            current_instruction = self._current_next_step_instruction(current_analyst_feedback or [])
            query_data = {
                'investigation_context': context,
                'previous_queries': [step['query'] for step in self.investigation_history],
                'discovered_threats': self.discovered_threats,
                'analyst_feedback': self._feedback_history_without_stale_next_step_instructions(analyst_feedback or []),
                'current_analyst_instruction': current_instruction,
                'force_current_analyst_instruction': bool(current_instruction)
            }
            
            return await self.llm.analyze_security_pattern("agent_query_generation", query_data)
        except Exception as e:
            logger.error(f"Failed to generate investigation query: {str(e)}")
            return {}

    def _current_next_step_instruction(self, analyst_feedback: List[Dict[str, Any]]) -> str:
        """Return the one-shot analyst override instruction for the current step only."""
        for feedback in reversed(analyst_feedback or []):
            if feedback.get('next_step_decision') == 'override':
                return str(feedback.get('custom_instruction') or '').strip()
        return ""

    async def _attach_next_query_proposal(
        self,
        investigation_step: Dict[str, Any],
        context: str,
        iteration: int,
        analyst_feedback: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """Generate a concrete next Cypher proposal for HITL review without executing it."""
        try:
            next_query_response = await self._generate_investigation_query_with_retry(
                context or DEFAULT_HITL_FOLLOWUP_CONTEXT,
                iteration,
                analyst_feedback or [],
                []
            )
            if not self._is_valid_query_response(next_query_response):
                return

            next_query = self._prepare_cypher_query_for_execution(next_query_response['cypher_query'])
            next_query_response['cypher_query'] = next_query
            explanation = (
                next_query_response.get('expected_findings') or
                f"Next step will investigate {next_query_response.get('investigation_focus', 'a distinct target')}."
            )

            analysis = investigation_step.setdefault('analysis', {})
            analysis['next_investigation_explanation'] = explanation
            analysis['next_investigation_context'] = next_query
            analysis['next_cypher_query'] = next_query
            analysis['next_query_generation'] = next_query_response
        except Exception as e:
            logger.warning(f"Failed to generate HITL next query proposal: {str(e)}")

    def _feedback_history_without_stale_next_step_instructions(
        self,
        analyst_feedback: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Keep verdict history while preventing old free-form next-step commands from being reused."""
        cleaned_feedback = []
        for feedback in analyst_feedback or []:
            if not isinstance(feedback, dict):
                continue

            cleaned = dict(feedback)
            if cleaned.get('custom_instruction'):
                cleaned['custom_instruction'] = ''
                cleaned['custom_instruction_note'] = 'One-shot instruction already applied in its original step.'
            if cleaned.get('llm_next_step'):
                cleaned['llm_next_step'] = ''
            cleaned_feedback.append(cleaned)

        return cleaned_feedback
    
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
                        if len(records) >= MAX_AGENT_QUERY_RESULTS:
                            break
            
            logger.info(f"Query returned {len(records)} records")
            return records, None
            
        except Exception as e:
            error_message = f"Cypher query execution failed: {str(e)}"
            logger.error(error_message)
            return [], error_message

    def _extract_direct_cypher_from_context(self, context: str, strict: bool = False) -> Optional[str]:
        """Return a safe Cypher query when the HITL next step is already Cypher."""
        query = self._candidate_cypher_from_context(context)
        if not query:
            return None

        try:
            return self._validate_read_only_cypher(query)
        except ValueError as e:
            logger.warning(f"HITL context looked like Cypher but was not safe to execute directly: {str(e)}")
            if strict:
                raise
            return None

    def _candidate_cypher_from_context(self, context: str) -> Optional[str]:
        """Extract a Cypher-looking query from HITL context without validating it."""
        text = (context or "").strip()
        if not text:
            return None

        fenced_match = re.search(r"```(?:cypher)?\s*(.*?)```", text, re.IGNORECASE | re.DOTALL)
        if fenced_match:
            text = fenced_match.group(1).strip()

        start_match = re.search(r"\b(MATCH|WITH)\b", text, re.IGNORECASE)
        if not start_match:
            return None

        query = text[start_match.start():].strip()
        if ";" in query:
            query = query.split(";", 1)[0].strip()

        return query

    def _requires_direct_cypher_execution(
        self,
        context: str,
        current_analyst_feedback: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """Require approved/supplied Cypher to be executed as-is or rejected visibly."""
        if not self._candidate_cypher_from_context(context):
            return False

        for feedback in reversed(current_analyst_feedback or []):
            if feedback.get('next_step_decision') in {'accept', 'override'}:
                return True

        return False

    def _create_rejected_direct_cypher_step(
        self,
        context: str,
        iteration: int,
        validation_error: str
    ) -> Dict[str, Any]:
        """Create a visible HITL step when approved/supplied Cypher is rejected before execution."""
        rejected_query = self._candidate_cypher_from_context(context) or context
        error_message = f"Approved or supplied Cypher was not executed: {validation_error}"
        return {
            'iteration': iteration + 1,
            'query': rejected_query,
            'focus': 'Rejected analyst-approved next step',
            'query_generation': {
                'cypher_query': rejected_query,
                'investigation_focus': 'Rejected analyst-approved next step',
                'expected_findings': 'The approved or supplied Cypher failed safety validation and was not executed.',
                'threat_indicators': [],
                'source': 'hitl_direct_cypher_rejected',
                'requested_context': context
            },
            'error': error_message,
            'results_count': 0,
            'analysis': {
                'error': True,
                'error_message': error_message,
                'threat_detected': False,
                'threat_type': 'none',
                'severity': 'low',
                'threat_description': error_message,
                'evidence': [],
                'investigation_complete': False,
                'next_investigation_context': DEFAULT_HITL_FOLLOWUP_CONTEXT,
                'next_investigation_explanation': (
                    'The approved next step could not be run safely. Continue with a different valid query or provide a revised instruction.'
                ),
                'recommendations': []
            }
        }

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

    def _prepare_cypher_query_for_execution(self, cypher_query: str) -> str:
        """Normalize agent Cypher before execution and before storing history."""
        query = self._validate_read_only_cypher(cypher_query)
        if self._is_ollama_provider():
            return self._add_ollama_safety_limits(query)
        return query
    
    def _add_safety_limits(self, cypher_query: str) -> str:
        """Add safety limits to Cypher query"""
        query = self._validate_read_only_cypher(cypher_query)

        if self._is_ollama_provider():
            return self._add_ollama_safety_limits(query)
        
        limit_pattern = re.compile(r"\bLIMIT\s+(\d+)\b", re.IGNORECASE)
        if limit_pattern.search(query):
            query = limit_pattern.sub(
                lambda match: f"LIMIT {min(int(match.group(1)), MAX_AGENT_QUERY_RESULTS)}",
                query
            )
        else:
            query += f" LIMIT {MAX_AGENT_QUERY_RESULTS}"
        
        return query

    def _is_ollama_provider(self) -> bool:
        return (self.config.provider or "").lower() == "ollama"

    def _add_ollama_safety_limits(self, cypher_query: str) -> str:
        """Keep Ollama agent queries small and rank-prioritized."""
        query = self._ensure_rank_return_for_ollama(cypher_query)
        query = re.sub(r"\bLIMIT\s+\d+\b", "", query, flags=re.IGNORECASE).strip()

        if self._uses_username_alias(query):
            if re.search(r"\bORDER\s+BY\b", query, re.IGNORECASE):
                query = re.sub(
                    r"\bORDER\s+BY\b.*$",
                    "ORDER BY u.rank DESC",
                    query,
                    flags=re.IGNORECASE | re.DOTALL
                ).strip()
            else:
                query = f"{query} ORDER BY u.rank DESC"

        return f"{query} LIMIT 15"

    def _ensure_rank_return_for_ollama(self, cypher_query: str) -> str:
        """Add rank to the returned fields so local analysis can see priority."""
        query = cypher_query.strip()
        if not self._uses_username_alias(query) or self._return_includes_username_rank(query):
            return query

        boundary = re.search(r"\bORDER\s+BY\b|\bLIMIT\b", query, re.IGNORECASE)
        if boundary:
            head = query[:boundary.start()].rstrip()
            tail = query[boundary.start():].lstrip()
        else:
            head = query
            tail = ""

        if not re.search(r"\bRETURN\b", head, re.IGNORECASE):
            return query

        query = f"{head}, u.rank AS rank"
        if tail:
            query = f"{query} {tail}"
        return query

    def _return_includes_username_rank(self, cypher_query: str) -> bool:
        return_match = re.search(r"\bRETURN\b(?P<return_fields>.*?)(?:\bORDER\s+BY\b|\bLIMIT\b|$)", cypher_query, re.IGNORECASE | re.DOTALL)
        if not return_match:
            return False
        return bool(re.search(r"\bu\.rank\b", return_match.group("return_fields"), re.IGNORECASE))

    def _uses_username_alias(self, cypher_query: str) -> bool:
        return bool(re.search(r"\(\s*u\s*:\s*Username\b", cypher_query, re.IGNORECASE))

    def _validate_read_only_cypher(self, cypher_query: str) -> str:
        """Conservatively allow only read-only Cypher generated by the agent."""
        query = (cypher_query or "").strip()
        if not query:
            raise ValueError("Empty Cypher query")
        if len(query) > MAX_AGENT_CYPHER_CHARS:
            raise ValueError("Cypher query is too long")

        # Reject comments and multi-statements to avoid hiding or chaining writes.
        if "--" in query or "/*" in query or "*/" in query:
            raise ValueError("Cypher comments are not allowed")

        stripped = query.rstrip(";").strip()
        if ";" in stripped:
            raise ValueError("Multiple Cypher statements are not allowed")
        query = stripped

        if not re.match(r"^MATCH\b", query, re.IGNORECASE):
            raise ValueError("Only MATCH read queries are allowed")
        if not re.search(r"\bRETURN\b", query, re.IGNORECASE):
            raise ValueError("Read queries must include RETURN")
        if len(re.findall(r"\bMATCH\b", query, re.IGNORECASE)) != 1:
            raise ValueError("Only one MATCH clause is allowed")

        blocked_patterns = [
            r"\bOPTIONAL\s+MATCH\b",
            r"\bUNION\b",
            r"\bCREATE\b",
            r"\bMERGE\b",
            r"\bSET\b",
            r"\bDELETE\b",
            r"\bDETACH\b",
            r"\bREMOVE\b",
            r"\bDROP\b",
            r"\bALTER\b",
            r"\bGRANT\b",
            r"\bDENY\b",
            r"\bREVOKE\b",
            r"\bCALL\b",
            r"\bLOAD\s+CSV\b",
            r"\bFOREACH\b",
            r"\bUNWIND\b",
            r"\bWITH\b",
            r"\bUSE\b",
            r"\bSTART\b",
            r"\bSTOP\b",
            r"\bSHOW\b",
            r"\bYIELD\b",
            r"\bSKIP\b",
            r"\bCASE\b",
            r"\bAPOC\.",
            r"\bDBMS\."
        ]
        for pattern in blocked_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                raise ValueError("Only read-only MATCH/RETURN Cypher is allowed")

        if re.search(r"\[[^\]]*\*", query):
            raise ValueError("Variable-length relationship patterns are not allowed")
        if re.search(r"\b(shortestPath|allShortestPaths|collect|count|size|reduce|range|keys|labels|type|id|elementId|coalesce|toInteger|toString|datetime|date|duration|split|substring|replace)\s*\(", query, re.IGNORECASE):
            raise ValueError("Cypher functions and aggregations are not allowed")

        self._validate_cypher_schema_allowlist(query)

        return query

    def _validate_cypher_schema_allowlist(self, query: str) -> None:
        """Allow only the labels, relationship types, aliases, and properties used by LogonTracer."""
        aliases = {}
        query_without_literals = self._cypher_without_string_literals(query)

        for var_name, label in re.findall(r"\(\s*([A-Za-z][A-Za-z0-9_]*)\s*:\s*([A-Za-z][A-Za-z0-9_]*)\b", query_without_literals):
            if label not in ALLOWED_CYPHER_LABELS:
                raise ValueError(f"Node label is not allowed: {label}")
            aliases[var_name] = label

        for rel_name, rel_type in re.findall(r"\[\s*([A-Za-z][A-Za-z0-9_]*)\s*:\s*([A-Za-z][A-Za-z0-9_]*)\b", query_without_literals):
            if rel_type not in ALLOWED_CYPHER_REL_TYPES:
                raise ValueError(f"Relationship type is not allowed: {rel_type}")
            aliases[rel_name] = rel_type

        for label in re.findall(r"(?<![A-Za-z0-9_]):\s*([A-Za-z][A-Za-z0-9_]*)\b", query_without_literals):
            if label not in ALLOWED_CYPHER_LABELS and label not in ALLOWED_CYPHER_REL_TYPES:
                raise ValueError(f"Schema label/type is not allowed: {label}")

        for alias, prop in re.findall(r"\b([A-Za-z][A-Za-z0-9_]*)\.([A-Za-z][A-Za-z0-9_]*)\b", query_without_literals):
            label = aliases.get(alias)
            if not label:
                raise ValueError(f"Property alias is not defined in MATCH: {alias}")
            if prop not in ALLOWED_CYPHER_PROPERTIES.get(label, set()):
                raise ValueError(f"Property is not allowed for {label}: {prop}")

    def _cypher_without_string_literals(self, query: str) -> str:
        """Remove string contents before schema token scanning."""
        string_literal_pattern = r"'(?:\\.|''|[^'\\])*'|\"(?:\\.|\"\"|[^\"\\])*\""
        return re.sub(string_literal_pattern, "''", query or "")
    
    async def _analyze_query_results(
        self,
        query: str,
        results: List[Dict],
        focus: str,
        iteration: int,
        analyst_feedback: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Analyze query results using LLM"""
        try:
            analysis_data = {
                'cypher_query': query,
                'investigation_focus': focus,
                'results': results,
                'results_count': len(results),
                'previous_findings': self.discovered_threats,
                'iteration': iteration,
                'max_iterations': self.max_iterations,
                'analyst_feedback': analyst_feedback or []
            }
            
            return await self.llm.analyze_security_pattern("agent_result_analysis", analysis_data)
        except Exception as e:
            logger.error(f"Failed to analyze query results: {str(e)}")
            return {
                'threat_detected': False,
                'error': str(e),
                'investigation_complete': False
            }

    async def _analyze_query_results_with_retry(
        self,
        query: str,
        results: List[Dict],
        focus: str,
        iteration: int,
        analyst_feedback: Optional[List[Dict[str, Any]]] = None,
        investigation_context: str = ""
    ) -> Dict[str, Any]:
        """Analyze query results and reject parser fallbacks or empty LLM output."""
        max_retries = 2

        for retry_attempt in range(max_retries):
            analysis_response = await self._analyze_query_results(
                query,
                results,
                focus,
                iteration,
                analyst_feedback
            )

            if self._is_valid_analysis_response(analysis_response):
                return analysis_response

            logger.warning(
                "Invalid result-analysis response received "
                f"(attempt {retry_attempt + 1}/{max_retries}) for iteration {iteration + 1}: {analysis_response}"
            )
            self._add_analysis_response_error(query, focus, iteration, analysis_response, retry_attempt)

            if retry_attempt < max_retries - 1:
                await asyncio.sleep(1)

        return self._create_analysis_failure_response(investigation_context)

    def _is_valid_analysis_response(self, response: Dict[str, Any]) -> bool:
        """Check whether an agent result-analysis response can drive investigation state."""
        if not response or response.get('error'):
            return False

        if not isinstance(response.get('threat_detected'), bool):
            return False
        if not isinstance(response.get('investigation_complete'), bool):
            return False
        if not isinstance(response.get('evidence'), list):
            return False
        if not str(response.get('threat_description', '')).strip():
            return False
        if response.get('threat_detected') and not response.get('evidence'):
            return False

        threat_type = str(response.get('threat_type', '')).lower()
        if threat_type not in {
            'lateral_movement',
            'privilege_escalation',
            'credential_theft',
            'brute_force',
            'insider_threat',
            'none'
        }:
            return False

        severity = str(response.get('severity', '')).lower()
        if severity not in {'low', 'medium', 'high', 'critical'}:
            return False

        return True

    def _create_no_results_analysis(self, next_investigation_context: str = DEFAULT_HITL_FOLLOWUP_CONTEXT) -> Dict[str, Any]:
        """Create deterministic analysis for an empty Neo4j result set."""
        return {
            'threat_detected': False,
            'threat_type': 'none',
            'severity': 'low',
            'no_results': True,
            'threat_description': (
                "No records matched this Neo4j query. No anomaly was found for this investigation step."
            ),
            'evidence': [],
            'investigation_complete': False,
            'next_investigation_context': next_investigation_context or DEFAULT_HITL_FOLLOWUP_CONTEXT,
            'next_investigation_explanation': (
                'Continue with the next distinct investigation target to keep coverage broad.'
            ),
            'recommendations': []
        }

    def _create_analysis_failure_response(self, investigation_context: str) -> Dict[str, Any]:
        """Create a non-decision response when LLM result analysis cannot be trusted."""
        return {
            'error': True,
            'analysis_failed': True,
            'error_message': 'LLM result analysis failed after retries',
            'threat_detected': False,
            'threat_type': 'none',
            'severity': 'low',
            'threat_description': (
                'The query returned records, but the LLM did not provide a valid structured analysis. '
                'This step was not used as threat evidence.'
            ),
            'evidence': [],
            'investigation_complete': False,
            'next_investigation_context': investigation_context,
            'next_investigation_explanation': (
                'Continue with a distinct investigation target because this result analysis was inconclusive.'
            ),
            'recommendations': []
        }
    
    async def _generate_final_report(
        self,
        analyst_feedback: Optional[List[Dict[str, Any]]] = None,
        completion_reason: str = "llm_completed"
    ) -> Dict[str, Any]:
        """Generate final investigation report"""
        try:
            report_data = {
                'investigation_history': self._get_reportable_investigation_history(),
                'discovered_threats': self.discovered_threats,
                'analyst_feedback': analyst_feedback or [],
                'completion_reason': completion_reason,
                'investigation_summary': {
                    'total_iterations': len(self._get_reportable_investigation_history()),
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
    
    async def _generate_investigation_query_with_retry(
        self,
        context: str,
        iteration: int,
        analyst_feedback: Optional[List[Dict[str, Any]]] = None,
        current_analyst_feedback: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Generate Cypher query with retry logic for errors and empty responses"""
        max_retries = 3
        analyst_feedback = analyst_feedback or []
        current_analyst_feedback = current_analyst_feedback or []
        current_instruction = self._current_next_step_instruction(current_analyst_feedback)
        
        for retry_attempt in range(max_retries):
            try:
                # Get recent errors to inform the LLM
                recent_errors = self._get_recent_query_errors()
                
                query_data = {
                    'investigation_context': context,
                    'previous_queries': self._get_previous_queries(),
                    'discovered_threats': self.discovered_threats,
                    'recent_errors': recent_errors,
                    'retry_attempt': retry_attempt,
                    'iteration': iteration,
                    'analyst_feedback': self._feedback_history_without_stale_next_step_instructions(analyst_feedback),
                    'current_analyst_instruction': current_instruction,
                    'force_current_analyst_instruction': bool(current_instruction)
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
                    self._add_empty_response_error(response, retry_attempt)
                        
            except Exception as e:
                logger.error(f"Failed to generate investigation query (attempt {retry_attempt + 1}): {str(e)}")
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

        try:
            self._validate_read_only_cypher(cypher_query)
        except ValueError:
            return False
        
        return True

    def _add_empty_response_error(self, response: Dict[str, Any], retry_attempt: int):
        """Track invalid LLM query-generation responses outside investigation history."""
        error_entry = {
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
        self.generation_errors.append(error_entry)

    def _add_generation_error(self, error_message: str, retry_attempt: int):
        """Track query-generation exceptions outside investigation history."""
        error_entry = {
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
        self.generation_errors.append(error_entry)

    def _add_analysis_response_error(
        self,
        query: str,
        focus: str,
        iteration: int,
        response: Dict[str, Any],
        retry_attempt: int
    ) -> None:
        """Track invalid result-analysis responses outside decision state."""
        self.analysis_errors.append({
            'iteration': iteration + 1,
            'retry_attempt': retry_attempt + 1,
            'query': query,
            'focus': focus,
            'error': f'Invalid result-analysis response from LLM: {response}',
            'error_type': 'analysis_response_error'
        })

    def _get_previous_queries(self) -> List[str]:
        """Return executed Cypher queries only, excluding LLM retry diagnostics."""
        return [
            step.get('query', '')
            for step in self.investigation_history
            if step.get('query')
        ]

    def _get_reportable_investigation_history(self) -> List[Dict[str, Any]]:
        """Return investigation steps that should influence the final report."""
        reportable_history = []
        for step in self.investigation_history:
            analysis = step.get('analysis', {})
            if analysis.get('analysis_failed'):
                continue
            iteration = step.get('iteration', '')
            if isinstance(iteration, str) and iteration.startswith('retry_'):
                continue
            reportable_history.append(step)
        return reportable_history

    def _get_recent_query_errors(self) -> List[Dict[str, Any]]:
        """Get recent Cypher execution errors from investigation history."""
        recent_errors = []
        
        # Only Neo4j execution errors should be fed to Cypher repair prompts.
        for step in self.investigation_history[-5:]:
            analysis = step.get('analysis', {})
            if step.get('query') and step.get('error'):
                error_info = {
                    'query': step.get('query', ''),
                    'error_message': step.get('error') or analysis.get('error_message', ''),
                    'focus': step.get('focus', ''),
                    'iteration': step.get('iteration', ''),
                    'error_type': 'execution_error'
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

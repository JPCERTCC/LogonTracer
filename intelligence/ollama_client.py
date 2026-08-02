"""
Ollama client for local LLM analysis.
"""
import asyncio
import json
import logging
from typing import Dict, Any, List

import openai

from .llm_config import LLMConfig
from .openai_client import OpenAIClient

logger = logging.getLogger(__name__)


class OllamaClient(OpenAIClient):
    """OpenAI-compatible Ollama client using shared LogonTracer prompts/parsers."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.client = openai.OpenAI(
            base_url=config.base_url.rstrip("/") + "/",
            api_key=config.api_key or "ollama"
        )

        super()._init_session_logging()

    async def analyze_security_pattern(self, query_type: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security patterns using an Ollama local model."""
        try:
            pagerank_data = self._get_pagerank_data_from_neo4j()
            prompt = self._build_security_prompt(query_type, analysis_data)
            system_prompt = "You are a senior DFIR analyst investigating Windows logons with JPCERT/CC LogonTracer."

            request_kwargs = {
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "temperature": self.config.temperature,
                "max_tokens": self._get_max_completion_tokens(query_type),
                "timeout": self.config.timeout,
                "extra_body": self._build_ollama_extra_body()
            }
            if self._supports_reasoning_effort():
                request_kwargs["reasoning_effort"] = self._get_reasoning_effort(query_type)

            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                **request_kwargs
            )

            content = response.choices[0].message.content or ""
            parsed_response = await self._parse_or_repair_security_response(
                query_type,
                content,
                request_kwargs,
                analysis_data
            )
            self._log_llm_interaction(query_type, prompt, system_prompt, content, parsed_response, analysis_data)
            return parsed_response

        except openai.APIConnectionError as e:
            logger.error(f"Ollama API Connection Error: {str(e)}")
            return self._create_ollama_connection_error_response()
        except openai.APITimeoutError as e:
            logger.error(f"Ollama API Timeout Error: {str(e)}")
            return self._create_timeout_error_response()
        except Exception as e:
            logger.error(f"Ollama API error: {str(e)}")
            return self._create_error_response(str(e))

    async def generate_sigma_rules(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Sigma rules from AI analysis results using an Ollama local model."""
        try:
            risk_level = (
                analysis_result.get('overall_risk_level') or
                analysis_result.get('risk_level') or
                analysis_result.get('final_report', {}).get('overall_risk_level') or
                'low'
            )
            if risk_level.lower() not in ['high', 'critical']:
                return {
                    'success': False,
                    'message': f'Sigma rule generation requires High or Critical risk level. Current level: {risk_level}',
                    'sigma_rules': []
                }

            prompt = self._build_sigma_generation_prompt(analysis_result)
            system_prompt = "You are a senior DFIR analyst investigating Windows logons with JPCERT/CC LogonTracer."

            request_kwargs = {
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "temperature": self.config.temperature,
                "max_tokens": self._get_max_completion_tokens('sigma_rule_generation'),
                "timeout": self.config.timeout,
                "extra_body": self._build_ollama_extra_body()
            }
            if self._supports_reasoning_effort():
                request_kwargs["reasoning_effort"] = self._get_reasoning_effort('sigma_rule_generation')

            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                **request_kwargs
            )

            content = response.choices[0].message.content or ""
            parsed_response = self._parse_sigma_response(content)
            self._log_llm_interaction('sigma_rule_generation', prompt, system_prompt, content, parsed_response, analysis_result)
            return parsed_response

        except Exception as e:
            logger.error(f"Ollama Sigma rule generation error: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to generate Sigma rules: {str(e)}',
                'sigma_rules': []
            }

    async def _parse_or_repair_security_response(
        self,
        query_type: str,
        content: str,
        original_request_kwargs: Dict[str, Any],
        analysis_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Parse an agent response, using one JSON-repair retry when needed."""
        parsed_response = self._parse_security_response(query_type, content)
        if not self._should_repair_agent_response(query_type, parsed_response, content, analysis_data):
            return parsed_response

        repaired_content = await self._repair_agent_json_response(
            query_type,
            content,
            original_request_kwargs,
            analysis_data
        )
        if not repaired_content:
            return parsed_response

        repaired_response = self._parse_security_response(query_type, repaired_content)
        if self._is_usable_agent_response(query_type, repaired_response):
            repaired_response["json_repaired"] = True
            return repaired_response

        logger.warning("Agent JSON repair did not produce a usable response")
        return parsed_response

    def _should_repair_agent_response(
        self,
        query_type: str,
        parsed_response: Dict[str, Any],
        content: str,
        analysis_data: Dict[str, Any]
    ) -> bool:
        """Repair only agent responses that are invalid or visibly partial."""
        if not query_type.startswith("agent_"):
            return False
        if not content:
            return False
        if query_type == "agent_result_analysis":
            if not self._has_minimum_result_analysis_repair_fields(content):
                return False
            if not self._has_result_analysis_repair_context(analysis_data):
                return False
        if parsed_response.get("partial_recovery"):
            return True
        return not self._is_usable_agent_response(query_type, parsed_response)

    def _has_minimum_result_analysis_repair_fields(self, content: str) -> bool:
        """Only repair result analysis when the response preserves the LLM's decision."""
        return all(
            self._has_json_field(content, field)
            for field in ["threat_detected", "threat_type", "severity", "threat_description"]
        )

    def _has_result_analysis_repair_context(self, analysis_data: Dict[str, Any]) -> bool:
        """Evidence can be reconstructed only when original query results are available."""
        return bool((analysis_data or {}).get("results"))

    def _is_usable_agent_response(self, query_type: str, response: Dict[str, Any]) -> bool:
        """Validate the minimum schema needed by the agent engine."""
        if not response or response.get("error"):
            return False

        if query_type in {"agent_query_generation", "agent_query_generation_with_errors"}:
            return bool(str(response.get("cypher_query", "")).strip())

        if query_type == "agent_result_analysis":
            if not isinstance(response.get("threat_detected"), bool):
                return False
            if not isinstance(response.get("investigation_complete"), bool):
                return False
            if not str(response.get("threat_description", "")).strip():
                return False
            if not isinstance(response.get("evidence"), list):
                return False
            if response.get("threat_detected") and not response.get("evidence"):
                return False
            if str(response.get("threat_type", "")).lower() not in {
                "lateral_movement",
                "privilege_escalation",
                "credential_theft",
                "brute_force",
                "insider_threat",
                "none"
            }:
                return False
            return str(response.get("severity", "")).lower() in {
                "low",
                "medium",
                "high",
                "critical"
            }

        if query_type == "agent_final_report":
            return all(key in response for key in [
                "analysis_summary",
                "overall_risk_level",
                "threats_summary",
                "recommendations",
                "detection_rules"
            ])

        return True

    async def _repair_agent_json_response(
        self,
        query_type: str,
        content: str,
        original_request_kwargs: Dict[str, Any],
        analysis_data: Dict[str, Any]
    ) -> str:
        """Ask the local model to repair JSON syntax without changing the analysis."""
        repair_prompt = f"""
        Repair the following incomplete or invalid JSON response for query_type={query_type}.

        Rules:
        - Return valid JSON only.
        - Preserve the original analysis, values, Cypher, severity, and evidence wherever present.
        - Do not add new security conclusions.
        - Only add missing required keys with conservative defaults if the original response omitted them.
        - For agent_result_analysis, reconstruct evidence ONLY from the original query results below.
        - Do not invent evidence that is not present in the original query results.
        - Preserve threat_detected, threat_type, severity, and threat_description from the original response.
        - Do not wrap the JSON in markdown.

        Required schema:
        {self._get_agent_repair_schema(query_type)}

        Original query context:
        {self._build_agent_repair_context(query_type, analysis_data)}

        Original response:
        {content}
        """

        repair_kwargs = {
            "model": original_request_kwargs["model"],
            "messages": [
                {
                    "role": "system",
                    "content": "You repair malformed JSON. You do not perform new security analysis."
                },
                {"role": "user", "content": repair_prompt}
            ],
            "temperature": 0,
            "max_tokens": min(max(self._get_max_completion_tokens(query_type), 1024), 4096),
            "timeout": self.config.timeout,
            "extra_body": self._build_ollama_extra_body()
        }

        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                **repair_kwargs
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.warning(f"Agent JSON repair failed: {str(e)}")
            return ""

    def _build_agent_repair_context(self, query_type: str, analysis_data: Dict[str, Any]) -> str:
        """Provide compact evidence context for JSON repair without changing prompts."""
        if query_type != "agent_result_analysis":
            return "No additional context required."

        context = {
            "cypher_query": (analysis_data or {}).get("cypher_query", ""),
            "investigation_focus": (analysis_data or {}).get("investigation_focus", ""),
            "results_count": (analysis_data or {}).get("results_count", 0),
            "results": ((analysis_data or {}).get("results") or [])[:15]
        }
        return json.dumps(context, indent=2, ensure_ascii=False)

    def _get_agent_repair_schema(self, query_type: str) -> str:
        if query_type in {"agent_query_generation", "agent_query_generation_with_errors"}:
            return """
            {
              "cypher_query": "MATCH ... RETURN ... LIMIT 15",
              "investigation_focus": "short phrase",
              "expected_findings": "short sentence",
              "threat_indicators": ["indicator"]
            }
            """

        if query_type == "agent_result_analysis":
            return """
            {
              "threat_detected": true,
              "threat_type": "lateral_movement|privilege_escalation|credential_theft|brute_force|insider_threat|none",
              "severity": "low|medium|high|critical",
              "threat_description": "evidence-grounded description",
              "evidence": ["evidence string"],
              "investigation_complete": false,
              "next_investigation_explanation": "short sentence",
              "next_investigation_context": "next Cypher query or short context",
              "recommendations": ["action"]
            }
            """

        if query_type == "agent_final_report":
            return """
            {
              "analysis_summary": "summary",
              "overall_risk_level": "low|medium|high|critical",
              "threats_summary": {
                "total_threats": 0,
                "critical_threats": 0,
                "threat_types": []
              },
              "recommendations": {
                "immediate": [],
                "short_term": [],
                "long_term": []
              },
              "detection_rules": []
            }
            """

        return "{}"

    def _build_ollama_extra_body(self) -> Dict[str, Any]:
        extra_body: Dict[str, Any] = {}
        options: Dict[str, Any] = {}

        if self.config.context_length:
            options["num_ctx"] = self.config.context_length
        if options:
            extra_body["options"] = options
        if self.config.keep_alive:
            extra_body["keep_alive"] = self.config.keep_alive

        return extra_body

    def _build_agent_query_prompt(self, data: Dict[str, Any]) -> str:
        """Build an Ollama-specific query prompt with smaller result limits."""
        prompt = super()._build_agent_query_prompt(data)
        return self._apply_ollama_query_limits_to_prompt(prompt)

    def _build_agent_query_prompt_with_errors(self, data: Dict[str, Any]) -> str:
        """Build an Ollama-specific retry prompt with smaller result limits."""
        prompt = super()._build_agent_query_prompt_with_errors(data)
        return self._apply_ollama_query_limits_to_prompt(prompt)

    def _build_agent_analysis_prompt(self, data: Dict[str, Any]) -> str:
        """Build an Ollama-specific result-analysis prompt with smaller next-step limits."""
        local_data = dict(data)
        local_data["results"] = (data.get("results") or [])[:15]
        prompt = super()._build_agent_analysis_prompt(local_data)
        return self._apply_ollama_query_limits_to_prompt(prompt)

    def _apply_ollama_query_limits_to_prompt(self, prompt: str) -> str:
        """Ask Ollama to keep generated Cypher small and rank-prioritized."""
        prompt = prompt.replace(
            "- No OPTIONAL MATCH / UNION / subqueries / variable-length (*) / APOC / aggregations / ORDER BY",
            "- No OPTIONAL MATCH / UNION / subqueries / variable-length (*) / APOC / aggregations"
        )
        prompt = prompt.replace(
            "- Return minimal fields; ALWAYS add LIMIT 1000",
            "- Return minimal fields; ALWAYS add u.rank AS rank, ORDER BY u.rank DESC, and LIMIT 15"
        )
        prompt = prompt.replace(
            "- Return fields (not whole nodes); ALWAYS add LIMIT 1000",
            "- Return fields (not whole nodes); ALWAYS add u.rank AS rank, ORDER BY u.rank DESC, and LIMIT 15"
        )
        prompt = prompt.replace("LIMIT 1000", "LIMIT 15")
        prompt = prompt.replace("first 1000", "first 15")

        local_rules = """

        OLLAMA LOCAL LLM QUERY LIMITS
        - For every generated or proposed Neo4j Cypher query, return only the 15 highest-rank records.
        - Include u.rank AS rank in RETURN whenever Username alias u is used.
        - Add ORDER BY u.rank DESC immediately before LIMIT 15.
        - Never use LIMIT greater than 15.
        """
        return prompt + local_rules

    def _build_agent_report_prompt(self, data: Dict[str, Any]) -> str:
        """Build a compact final-report prompt for local LLMs."""
        compact_data = self._compact_agent_report_data(data)

        return f"""
        You are generating the final cybersecurity investigation report for JPCERT/CC LogonTracer.

        Use this compact investigation data. It has already removed raw duplicate event rows:
        {json.dumps(compact_data, indent=2, ensure_ascii=False)}

        Rules:
        - Use only evidence present in the compact data.
        - Do not treat missing 4625 events as benign.
        - Do not escalate severity from LogonType=0 or authname='-' alone.
        - If a detected threat exists, keep its threat_type and severity unless the evidence contradicts it.
        - Mention concrete users, hosts, IPs, Event.id, logintype, authname, servicename, ticketencryptiontype, and status when available.
        - Return valid JSON only. Do not use markdown, comments, or trailing commas.

        Return exactly this JSON object:
        {{
          "analysis_summary": "Concise 4-6 sentence synthesis naming the top account/host and why it matters.",
          "overall_risk_level": "low|medium|high|critical",
          "threats_summary": {{
            "total_threats": 0,
            "critical_threats": 0,
            "threat_types": ["lateral_movement|privilege_escalation|credential_theft|brute_force|insider_threat"]
          }},
          "recommendations": {{
            "immediate": ["Specific containment or credential action tied to named evidence"],
            "short_term": ["Focused validation or hardening action"],
            "long_term": ["Strategic detection or account-management improvement"]
          }},
          "detection_rules": [
            "Rule-style statement aligned to the evidence and LogonTracer fields"
          ]
        }}
        """

    def _compact_agent_report_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Reduce final-report context size for Ollama without losing evidence anchors."""
        return {
            "investigation_summary": data.get("investigation_summary", {}),
            "completion_reason": data.get("completion_reason", "llm_completed"),
            "detected_threats": [
                self._compact_threat(threat)
                for threat in data.get("discovered_threats", [])[:5]
            ],
            "timeline": [
                self._compact_timeline_step(step)
                for step in data.get("investigation_timeline", data.get("investigation_history", []))[:10]
            ],
            "analyst_feedback": (data.get("analyst_feedback") or [])[-5:]
        }

    def _compact_threat(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Keep only the final-report fields needed for one detected threat."""
        return {
            "iteration": threat.get("iteration"),
            "threat_type": threat.get("threat_type"),
            "severity": threat.get("severity"),
            "description": threat.get("description"),
            "evidence": (threat.get("evidence") or [])[:8],
            "query": threat.get("query"),
            "representative_results": self._compact_records(threat.get("results") or [], limit=5)
        }

    def _compact_timeline_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Keep a compact view of an investigation step."""
        analysis = step.get("analysis", {})
        return {
            "iteration": step.get("iteration"),
            "focus": step.get("focus"),
            "query": step.get("query"),
            "results_count": step.get("results_count", 0),
            "threat_detected": analysis.get("threat_detected"),
            "threat_type": analysis.get("threat_type"),
            "severity": analysis.get("severity"),
            "no_results": analysis.get("no_results", False),
            "analysis_failed": analysis.get("analysis_failed", False),
            "threat_description": analysis.get("threat_description"),
            "evidence": (analysis.get("evidence") or [])[:5],
            "recommendations": (analysis.get("recommendations") or [])[:3]
        }

    def _compact_records(self, records: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
        """Deduplicate and trim raw Neo4j records to representative evidence rows."""
        compact_records = []
        seen = set()
        wanted_fields = [
            "u.user",
            "i.hostname",
            "i.IP",
            "e.id",
            "e.logintype",
            "e.authname",
            "e.servicename",
            "e.ticketencryptiontype",
            "e.status",
            "u.rank"
        ]

        for record in records:
            compact_record = {
                field: record.get(field)
                for field in wanted_fields
                if record.get(field) is not None
            }
            key = tuple((field, compact_record.get(field)) for field in wanted_fields)
            if key in seen:
                continue
            seen.add(key)
            compact_records.append(compact_record)
            if len(compact_records) >= limit:
                break

        return compact_records

    def _supports_reasoning_effort(self) -> bool:
        """Limit reasoning_effort to gpt-oss models known to support it through Ollama."""
        return str(self.config.model or "").lower().startswith("gpt-oss")

    def _create_ollama_connection_error_response(self) -> Dict[str, Any]:
        return {
            "risk_level": "Unknown",
            "summary": "Unable to connect to the local Ollama service. Please check the Ollama container and base URL.",
            "key_findings": ["Local LLM service is unreachable"],
            "security_concerns": ["Automated threat detection is temporarily offline"],
            "recommendations": [
                "Verify the Ollama container is running",
                "Check the configured Ollama base URL",
                "Pull the selected model before running analysis",
                "Review LogonTracer and Ollama container logs"
            ]
        }

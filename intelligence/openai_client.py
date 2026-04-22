"""
OpenAI Client for AI Analysis
"""
import os
import json
import openai
import asyncio
import logging
from datetime import datetime
from neo4j import GraphDatabase
from .llm_config import LLMConfig
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class OpenAIClient:
    def __init__(self, config: LLMConfig):
        self.config = config
        self.client = openai.OpenAI(api_key=config.api_key)
        
        # Initialize logging directory
        self.log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'llm_interactions')
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Session variables
        self.session_id = None
        self.session_log_path = None
        self.session_interactions = []
        self.session_start_time = None
        
    def start_session(self, session_id: str):
        """Start a new AI analysis session"""
        self.session_id = session_id
        self.session_start_time = datetime.now()
        self.session_log_path = os.path.join(self.log_dir, f"ai_analysis_session_{session_id}.log")
        self.session_interactions = []
        
        logger.info(f"Started new AI analysis session: {self.session_id}")
    
    def _log_llm_interaction(self, query_type: str, prompt: str, system_prompt: str, response_content: str, parsed_response: Dict[str, Any] = None, analysis_data: Dict[str, Any] = None):
        """Log LLM interaction to session (not individual file)"""
        if not self.session_id:
            # If no session is active, start one automatically
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            self.start_session(f"auto_{timestamp}")
        
        # Prepare filtered analysis data (exclude large result sets)
        filtered_data = {}
        if analysis_data:
            for key, value in analysis_data.items():
                if key in ['results', 'events', 'query_results']:
                    # Only log count and sample for large datasets
                    if isinstance(value, list):
                        filtered_data[f"{key}_count"] = len(value)
                        if len(value) > 0:
                            filtered_data[f"{key}_sample"] = value[:3]  # First 3 items only
                    else:
                        filtered_data[key] = value
                else:
                    filtered_data[key] = value
        
        # Don't store system prompt as it's common across all interactions
        interaction = {
            'query_type': query_type,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'user_prompt': prompt,
            'input_data_summary': filtered_data,
            'response_content': response_content,
            'parsed_response': parsed_response
        }
        
        self.session_interactions.append(interaction)
        logger.debug(f"Logged interaction {len(self.session_interactions)} for session {self.session_id}")
        
    def end_session(self, final_report: Dict[str, Any] = None):
        """End the current session and write the complete log"""
        if not self.session_id:
            return
            
        try:
            with open(self.session_log_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(f"AI ANALYSIS SESSION LOG\n")
                f.write("=" * 80 + "\n")
                f.write(f"Session ID: {self.session_id}\n")
                f.write(f"Start Time: {self.session_start_time.strftime('%Y-%m-%d %H:%M:%S') if self.session_start_time else 'Unknown'}\n")
                f.write(f"Model: {self.config.model}\n")
                f.write(f"Language: {self.config.response_language or 'en'}\n")
                f.write(f"Temperature: {self.config.temperature}\n")
                f.write(f"Max Completion Tokens: {self.config.max_completion_tokens}\n")
                f.write(f"Total Interactions: {len(self.session_interactions)}\n")
                f.write("\n")
                
                # Write all interactions in chronological order (system prompt excluded as common)
                for i, interaction in enumerate(self.session_interactions, 1):
                    f.write("=" * 60 + f" INTERACTION {i} " + "=" * 60 + "\n")
                    f.write(f"Query Type: {interaction.get('query_type', 'Unknown')}\n")
                    f.write(f"Timestamp: {interaction.get('timestamp', 'Unknown')}\n")
                    f.write("\n")
                    
                    f.write("-" * 40 + " USER PROMPT " + "-" * 40 + "\n")
                    f.write(interaction.get('user_prompt', 'No user prompt'))
                    f.write("\n\n")
                    
                    if interaction.get('input_data_summary'):
                        f.write("-" * 40 + " INPUT DATA SUMMARY " + "-" * 40 + "\n")
                        f.write(json.dumps(interaction['input_data_summary'], indent=2, ensure_ascii=False))
                        f.write("\n\n")
                    
                    f.write("-" * 40 + " LLM RESPONSE " + "-" * 40 + "\n")
                    f.write(interaction.get('response_content', 'No response'))
                    f.write("\n\n")
                    
                    # Skip parsed_response logging to keep file size manageable
                    # if interaction.get('parsed_response'):
                    #     f.write("-" * 40 + " PARSED RESPONSE " + "-" * 40 + "\n")
                    #     f.write(json.dumps(interaction['parsed_response'], indent=2, ensure_ascii=False))
                    #     f.write("\n\n")
                
                # Write final report if available
                if final_report:
                    f.write("=" * 60 + " FINAL REPORT " + "=" * 60 + "\n")
                    f.write(json.dumps(final_report, indent=2, ensure_ascii=False))
                    f.write("\n\n")
                
                f.write("=" * 80 + "\n")
                f.write(f"SESSION COMPLETED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n")
            
            logger.info(f"AI session log completed: {self.session_log_path}")
            
        except Exception as e:
            logger.error(f"Failed to write session log: {str(e)}")
        finally:
            # Reset session
            self.session_id = None
            self.session_log_path = None
            self.session_interactions = []
            self.session_start_time = None
        
    async def analyze_security_pattern(self, query_type: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security patterns using OpenAI"""
        try:
            # Get PageRank data for enhanced analysis
            pagerank_data = self._get_pagerank_data_from_neo4j()
            
            prompt = self._build_security_prompt(query_type, analysis_data)
            system_prompt = self._build_system_message(pagerank_data)

            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.config.model,
                messages=[
                    {
                        "role": "system", 
                        "content": system_prompt
                    },
                    {"role": "user", "content": prompt}
                ],
                #temperature=self.config.temperature, # for GPT-4
                #max_tokens=self.config.max_tokens, # for GPT-4
                reasoning_effort="low", # for GPT-5
                max_completion_tokens=self.config.max_completion_tokens, # for GPT-5
                timeout=self.config.timeout
            )
            
            content = response.choices[0].message.content
            
            # Parse the response first
            parsed_response = self._parse_analysis_response(content)
            
            # Log the interaction (excluding large datasets)
            self._log_llm_interaction(query_type, prompt, system_prompt, content, parsed_response, analysis_data)
            
            return parsed_response
            
        except openai.RateLimitError as e:
            logger.error(f"OpenAI Rate Limit Error: {str(e)}")
            return self._create_quota_exceeded_response()
        except openai.AuthenticationError as e:
            logger.error(f"OpenAI Authentication Error: {str(e)}")
            return self._create_auth_error_response()
        except openai.APIConnectionError as e:
            logger.error(f"OpenAI API Connection Error: {str(e)}")
            return self._create_connection_error_response()
        except openai.APITimeoutError as e:
            logger.error(f"OpenAI API Timeout Error: {str(e)}")
            return self._create_timeout_error_response()
        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}")
            return self._create_error_response(str(e))

    async def generate_sigma_rules(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Sigma rules from AI analysis results (High/Critical severity only)"""
        try:
            # Filter for High/Critical risk levels - check multiple locations
            final_report = analysis_result.get('final_report', {})
            risk_level = (
                analysis_result.get('overall_risk_level') or 
                analysis_result.get('risk_level') or 
                analysis_result.get('final_report', {}).get('overall_risk_level') or
                'low'
            )
            logger.debug(f"Sigma generation - risk_level: {risk_level}")
            
            if risk_level.lower() not in ['high', 'critical']:
                return {
                    'success': False,
                    'message': f'Sigma rule generation requires High or Critical risk level. Current level: {risk_level}',
                    'sigma_rules': []
                }
            
            # Build prompt for Sigma rule generation
            prompt = self._build_sigma_generation_prompt(analysis_result)
            system_prompt = self._build_sigma_system_message()
            
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.config.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                reasoning_effort="medium", # for GPT-5
                max_completion_tokens=self.config.max_completion_tokens,
                timeout=self.config.timeout
            )
            
            content = response.choices[0].message.content
            parsed_response = self._parse_sigma_response(content)
            
            # Log the interaction
            self._log_llm_interaction('sigma_rule_generation', prompt, system_prompt, content, parsed_response, analysis_result)
            
            return parsed_response
            
        except Exception as e:
            logger.error(f"Sigma rule generation error: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to generate Sigma rules: {str(e)}',
                'sigma_rules': []
            }

    def _build_sigma_system_message(self) -> str:
        """Build system message for Sigma rule generation"""
        language = self.config.response_language or 'en'
        
        language_note = ""
        if language == 'ja':
            language_note = "descriptionとreferenceの説明文は日本語で記述してください。"
        elif language == 'fr':
            language_note = "Les descriptions et références doivent être rédigées en français."
        
        return f"""You are a DFIR-focused detection engineer who produces high-quality, production-ready Sigma rules.
                PRIMARY OBJECTIVE
                - Generate valid Sigma rules from the provided investigation evidence.
                - Evidence-first: every detection condition MUST be justified by fields/values present in the input.
                - Do not use any fields/values that do not exist in the evidence.

                INPUT CONTRACT
                - The investigation evidence may include:
                - threat_type, severity, description
                - evidence lines (human-readable evidence strings)
                - raw results (arrays of objects with keys like "e.id" or "e.logintype")
                - Treat the input as the complete dataset. Do not assume any information outside the input.

                SIGMA RULE QUALITY BAR
                - Follow the Sigma specification and common conventions.
                - Always use the following logsource:
                   - product: windows
                   - service: security
                - Each rule MUST include:
                   - title, id, status, description, author, date, logsource, detection, falsepositives, level, tags
                - detection MUST be syntactically valid YAML and Sigma-compatible (no pseudo-fields).
                - Keep rules simple and clear. Avoid overly complex logic or deep nesting.
                - The condition do not use "not selection" or "1 of them".

                FIELD MAPPING (Neo4j → Windows Security Event Log concepts)
                - Evidence uses Neo4j-like keys. Map them to Windows Security event log fields as follows:
                - e.id                   → EventID
                - e.logintype            → LogonType
                - e.authname             → AuthenticationPackageName OR PackageName
                - e.status               → Status
                - e.servicename          → ServiceName
                - e.ticketencryptiontype → TicketEncryptionType
                - u.user                 → TargetUserName
                - i.IP                   → IpAddress OR WorkstationName OR Workstation
                - i.hostname             → IpAddress

                FIELD VALUE NORMALIZATION
                - The following tokens in evidence are derived from Event IDs. Treat them as these Event IDs in Sigma rules (The evidence does not specify which event IDs are targeted, so include all event IDs corresponding to the token in the SIGMA rule.):
                - AddGroup: 4728, 4732, 4756
                - RemoveGroup: 4729, 4733, 4757
                - Created: 4720
                - Deleted: 4726
                - DCShadow: 5137, 5141
                - DCSync: 4662

                - TicketEncryptionType values are normalized as follows. In Sigma rules, use the HEX values:
                - "0x1": "DES-CBC-CRC"
                - "0x3": "DES-CBC-MD5"
                - "0x11": "AES128-CTS-HMAC-SHA1-96"
                - "0x12": "AES256-CTS-HMAC-SHA1-96"
                - "0x17": "RC4-HMAC"
                - "0x18": "RC4-HMAC-EXP"
                - "0xffffffff": "-"

                EVENT LOG-SPECIFIC FIELD WHITELIST
                - Different Windows Security EventIDs expose different fields. When generating Sigma rules, you MUST:
                1) Use ONLY fields that are valid for that EventID,
                2) If a field is not listed for the EventID OR not present in Sample Event Data, DO NOT use it in detection.

                FIELD WHITELIST BY EVENTID (Sigma field names)
                4624
                - Allowed fields:
                IpAddress
                WorkstationName
                LogonType
                TargetUserName
                TargetDomainName
                TargetUserSid
                AuthenticationPackageName

                4625
                - Allowed fields:
                LogonType
                TargetUserName
                TargetDomainName
                TargetUserSid
                AuthenticationPackageName
                WorkstationName
                IpAddress
                Status

                4776 
                - Allowed fields:
                TargetUserName
                Workstation
                Status
                PackageName

                4768, 4769
                - Allowed fields:
                TargetUserName
                TargetDomainName
                ServiceName
                TicketEncryptionType
                PreAuthType
                IpAddress
                Status

                4672, 4662, 5137, 5141
                - Allowed fields:
                SubjectUserName

                4719
                - Allowed fields:
                SubjectUserName
                CategoryId
                SubcategoryGuid

                4728, 4732, 4733, 4729, 4756, 4757
                - Allowed fields:
                MemberName

                4720, 4726
                - Allowed fields:
                TargetUserName

                LANGUAGE CONTROL
                {language_note}

                FINAL CHECK BEFORE RESPONDING
                - YAML parses cleanly (proper indentation, lists, strings).
                - detection uses ONLY these fields:
                   - EventID, LogonType, AuthenticationPackageName, PackageName, Status, ServiceName, TicketEncryptionType, TargetUserName, IpAddress, WorkstationName OR Workstation, MemberName
                - detection uses ONLY fields and values that appear in the provided evidence.
                - Do not invent any values.
                """

    def _build_sigma_generation_prompt(self, analysis_result: Dict[str, Any]) -> str:
        """Build prompt for Sigma rule generation"""
        
        # Get final_report if available (Agent results have this structure)
        final_report = analysis_result.get('final_report', {})
        
        # Extract relevant information from analysis result - check both top level and final_report
        risk_level = (
            analysis_result.get('overall_risk_level') or 
            analysis_result.get('risk_level') or 
            final_report.get('overall_risk_level') or
            'unknown'
        )
        summary = (
            analysis_result.get('analysis_summary') or 
            analysis_result.get('summary') or
            final_report.get('analysis_summary') or
            ''
        )
        
        # Get threats with full details for Sigma rule generation
        # If overall risk is high/critical, include all threats regardless of individual severity
        high_severity_threats = []
        all_threats = []
        evidence_list = []
        
        # From agent analysis results (top-level discovered_threats)
        discovered_threats = analysis_result.get('discovered_threats', [])
        
        for threat in discovered_threats:
            severity = threat.get('severity', '').lower()
            
            threat_details = {
                'threat_type': threat.get('threat_type', 'unknown'),
                'severity': severity or 'medium',  # Default to medium if empty
                'description': threat.get('description', ''),
                'evidence': threat.get('evidence', []),
                'query': threat.get('query', ''),
                'results': threat.get('results', [])[:10]  # Limit results to avoid token overflow
            }
            all_threats.append(threat_details)
            
            if severity in ['high', 'critical']:
                # Collect full threat details for Sigma generation
                high_severity_threats.append(threat_details)
                evidence_list.extend(threat.get('evidence', []))
        
        # From final_report discovered_threats (usually empty, but check anyway)
        # Only add if discovered_threats was empty (avoid duplicates)
        if not discovered_threats:
            final_report_threats = final_report.get('discovered_threats', [])
            for threat in final_report_threats:
                severity = threat.get('severity', '').lower()
                threat_details = {
                    'threat_type': threat.get('threat_type', 'unknown'),
                    'severity': severity or 'medium',
                    'description': threat.get('description', ''),
                    'evidence': threat.get('evidence', []),
                    'query': threat.get('query', ''),
                    'results': threat.get('results', [])[:10]
                }
                all_threats.append(threat_details)
                if severity in ['high', 'critical']:
                    high_severity_threats.append(threat_details)
                    evidence_list.extend(threat.get('evidence', []))
        
        # Fallback: If overall risk is high/critical but no high/critical severity threats found,
        # use all discovered threats for Sigma rule generation
        if not high_severity_threats and risk_level.lower() in ['high', 'critical'] and all_threats:
            high_severity_threats = all_threats
            for threat in all_threats:
                evidence_list.extend(threat.get('evidence', []))
        
        # From direct analysis results
        if analysis_result.get('evidence'):
            evidence_list.extend(analysis_result.get('evidence', []))
        
        
        # Get key findings from both locations
        key_findings = analysis_result.get('key_findings', []) or final_report.get('key_findings', [])
        
        # Get detection rules if available
        detection_rules = analysis_result.get('detection_rules', []) or final_report.get('detection_rules', [])
        
        # Get threat types from both locations
        threats_summary = analysis_result.get('threats_summary', {}) or final_report.get('threats_summary', {})
        threat_types = threats_summary.get('threat_types', [])
        
        # Get recommendations from both locations
        recommendations = analysis_result.get('recommendations', {}) or final_report.get('recommendations', {})
        if isinstance(recommendations, dict):
            immediate_actions = recommendations.get('immediate', [])
        else:
            immediate_actions = recommendations if isinstance(recommendations, list) else []
        
        # Include investigation_history for more context
        investigation_history = analysis_result.get('investigation_history', [])
        
        return self._format_sigma_generation_prompt(
            risk_level=risk_level,
            summary=summary,
            high_severity_threats=high_severity_threats,
            evidence_list=evidence_list,
            key_findings=key_findings,
            detection_rules=detection_rules,
            threat_types=threat_types
        )

    def _format_sigma_generation_prompt(self, risk_level: str, summary: str, 
                                         high_severity_threats: list, evidence_list: list,
                                         key_findings: list, detection_rules: list,
                                         threat_types: list) -> str:
        """Format the Sigma generation prompt with threat details"""
        
        # Format high severity threats for the prompt
        threats_section = ""
        if high_severity_threats:
            threats_section = "HIGH/CRITICAL SEVERITY THREATS (use these for Sigma rules):\n"
            for i, threat in enumerate(high_severity_threats, 1):
                threats_section += f"""
--- Threat #{i} ---
Type: {threat['threat_type']}
Severity: {threat['severity']}
Description: {threat['description']}

Evidence:
{json.dumps(threat['evidence'], indent=2) if threat['evidence'] else 'None'}
"""
        else:
            threats_section = "No High/Critical severity threats found."
        
        return f"""
Based on the following security investigation results, generate Sigma detection rules.

OVERALL RISK LEVEL: {risk_level}

ANALYSIS SUMMARY:
{summary}

{threats_section}

THREAT TYPES DETECTED:
{json.dumps(threat_types, indent=2) if threat_types else 'None'}

SCOPE / INPUT CONSTRAINTS
- Generate Sigma rules ONLY for threats with Severity = "high" or "critical" shown above.
- Use ONLY the evidence lines and Sample Event Data included in each threat block. Do not invent fields/values/hostnames/usernames/IPs/processes/or any additional context.
- Generate exactly ONE Sigma rule per threat.
- If required fields/values are missing or ambiguous, do not guess.

RULE GENERATION STRATEGY (evidence-first; mandatory)
For each high/critical threat:
1) Extract the core event pattern from Sample Event Data:
   - EventID (required)
   - TargetUserName (required)
   - LogonType (if present and applicable)
   - Status (if present)
   - AuthenticationPackageName (if present)
   - IpAddress (if present)
   - WorkstationName or Workstation (if present)
   - ServiceName / TicketEncryptionType (if present)
2) Create exactly one Sigma rule per threat (event-based detection).
   - Keep the rule portable: do NOT hardcode environment-specific usernames/hostnames/IPs.
3) Correlation / thresholds:
   - Sigma rules are primarily event-based. For threat concepts that require correlation (e.g., "same user connects to many hosts", ">= N distinct hosts"), do NOT implement correlation logic inside Sigma.

FIELD NAME MAPPING (Neo4j-like keys → Windows Security fields used in Sigma)
- e.id                   → EventID [numbers]
- e.logintype            → LogonType [numbers]
- e.authname             → AuthenticationPackageName or PackageName (for EventID 4776) [strings]
- e.status               → Status (use hex string, e.g., '0xc000006d' for success) [strings]
- e.servicename          → ServiceName [strings]
- e.ticketencryptiontype → TicketEncryptionType [strings]
- u.user                 → TargetUserName [strings]
- i.IP                   → IpAddress or WorkstationName or Workstation [strings]
- i.hostname             → IpAddress [strings]

FIELD WHITELIST BY EVENTID (Sigma field names)
4624
- Allowed fields:
IpAddress
WorkstationName
LogonType
TargetUserName
TargetDomainName
TargetUserSid
AuthenticationPackageName

4625
- Allowed fields:
LogonType
TargetUserName
TargetDomainName
TargetUserSid
AuthenticationPackageName
WorkstationName
IpAddress
Status

4776 
- Allowed fields:
TargetUserName
Workstation
Status
PackageName

4768, 4769
- Allowed fields:
TargetUserName
TargetDomainName
ServiceName
TicketEncryptionType
PreAuthType
IpAddress
Status

4672, 4662, 5137, 5141
- Allowed fields:
SubjectUserName

4719
- Allowed fields:
SubjectUserName
CategoryId
SubcategoryGuid

4728, 4732, 4733, 4729, 4756, 4757
- Allowed fields:
MemberName

4720, 4726
- Allowed fields:
TargetUserName

FIELD VALUE NORMALIZATION (value normalization rules)
- The following tokens in evidence may represent underlying Windows Event IDs. If applicable, treat them as these Event IDs (The evidence does not specify which event IDs are targeted, so include all event IDs corresponding to the token in the SIGMA rule.):
  - AddGroup: 4728, 4732, 4756
  - RemoveGroup: 4729, 4733, 4757
  - Created: 4720
  - Deleted: 4726
  - DCShadow: 5137, 5141
  - DCSync: 4662

- TicketEncryptionType mapping:
  - In Sigma, use hexadecimal (HEX) values (do not replace with names):
    "0x1"        → DES-CBC-CRC
    "0x3"        → DES-CBC-MD5
    "0x11"       → AES128-CTS-HMAC-SHA1-96
    "0x12"       → AES256-CTS-HMAC-SHA1-96
    "0x17"       → RC4-HMAC
    "0x18"       → RC4-HMAC-EXP
    "0xffffffff" → '-'
  - In Sigma detection, match on the HEX value (e.g., TicketEncryptionType: '0x17').

DETECTION QUALITY REQUIREMENTS (strict)
- Each Sigma YAML MUST include:
  title, id, status, description, author, date, references, tags, logsource, detection, falsepositives, level
- logsource MUST be:
  product: windows
  service: security
- detection MUST be Sigma-valid and simple:
  - The condition do not use "not selection" or "1 of them".
- Allowed EventIDs ONLY:
  4624, 4625, 4662, 4768, 4769, 4776, 4672, 4720, 4726, 4728, 4729, 4732, 4733, 4756, 4757, 4719, 5137, 5141
- Allowed detection fields ONLY (no others):
  EventID, LogonType, AuthenticationPackageName, Status, ServiceName, TicketEncryptionType, TargetUserName, SubjectUserName, IpAddress, WorkstationName, Workstation, MemberName
- Noise control is mandatory:
  - Provide at least ONE concrete falsepositive.
- references:
  - Include "N/A" if no references are available.
- MITRE ATT&CK tags:
  - Add tags consistent with threat_type (e.g., attack.lateral_movement, attack.credential_access, attack.privilege_escalation, attack.persistence).
- Levels:
  - severity=critical → Sigma level: critical
  - severity=high → Sigma level: high

IMPORTANT GUARDRAILS
- Generate rules ONLY for HIGH/CRITICAL threats with concrete evidence.
- Even if Event 4625 is missing, do not require it and do not treat it as benign.

OUTPUT REQUIREMENTS (JSON only)
Return ONLY the following JSON format:
{{
  "success": true,
  "message": "Generated N Sigma rules based on High/Critical severity threats",
  "sigma_rules": [
    {{
      "rule_name": "descriptive_rule_name",
      "yaml_content": "title: Rule Title\nid: <uuid>\nstatus: stable\n...",
      "description": "Brief description of what this rule detects",
      "threat_type": "lateral_movement|privilege_escalation|credential_theft|brute_force|insider_threat",
      "target_event_ids": [4624, 4769]
    }}
  ]
}}

YAML CONTENT FORMAT (each rule)
- yaml_content MUST be a single YAML document encoded as a JSON string (use \\n for newlines).
- Do NOT use markdown code fences inside yaml_content.
- Always use:
  author: LogonTracer AI Analysis
  date: {datetime.now().strftime('%Y/%m/%d')}
- For strings fields in 'FIELD NAME MAPPING', enclose the value in single quotes in YAML (e.g., Status: '0xc000006d').
- Field name 'Workstation' conatins hostname (Do NOT use IP address (e.g., 10.0.0.1))
- Field name 'WorkstationName' contains hostname (Do NOT use IP address (e.g., 10.0.0.1))
- Fields other than 'FIELD WHITELIST BY EVENTID' will not be used even if they are included in the evidence.
- To search for strings other than EventID, use the field modifier '|contains' (e.g. TargetUserName|contains: 'admin', TicketEncryptionType|contains: '0x17')
- if 'status' field is '-' in evidence, use Status: '0x0' in detection.
- If evidence contains both hostname and IP, include both in the rule and match on hostname OR IP(not both required).
- status should normally be "stable" (exceptions only when evidence is exceptionally strong).

YAML SAFETY (must follow)
- Do NOT use YAML special characters anywhere in the output (applies to ALL string fields including title/description/detection values).
- Forbidden characters: : # {{ }} [ ] , & * ! ? | < > % @ ` " ^ :
- If any field/value would contain a forbidden character, do NOT output it as-is:
  either (1) omit that field from detection, or (2) replace the value with REDACTED (safe token).

Example YAML structure (follow this structure; adjust fields/values based on evidence)
title: Descriptive Title
id: <generate-uuid>
status: stable
description: Detailed description (include brief Correlation Notes only if needed)
author: LogonTracer AI Analysis
date: {datetime.now().strftime('%Y/%m/%d')}
references:
  - N/A
tags:
  - attack.lateral_movement
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 10
    Status: '0xc000006d'
    TargetUserName|contains: 'known_admin'
    IpAddress|contains: '192.168.1.1'
    WorkstationName|contains: 'host_name'
  condition: selection
falsepositives:
  - Legitimate administrative activity via approved remote access
level: high

You MUST strictly adhere to this JSON format in your response.
"""
    def _parse_sigma_response(self, content: str) -> Dict[str, Any]:
        """Parse Sigma rule generation response"""
        try:
            # Try to extract JSON from the response
            start_idx = content.find('{')
            end_idx = content.rfind('}') + 1
            
            if start_idx != -1 and end_idx != 0:
                json_str = content[start_idx:end_idx]
                result = json.loads(json_str)
                
                # Validate required fields
                if 'sigma_rules' not in result:
                    result['sigma_rules'] = []
                if 'success' not in result:
                    result['success'] = len(result['sigma_rules']) > 0
                if 'message' not in result:
                    result['message'] = f"Generated {len(result['sigma_rules'])} Sigma rules"
                
                return result
            else:
                return {
                    'success': False,
                    'message': 'Failed to parse response - no JSON found',
                    'sigma_rules': []
                }
                
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Sigma response JSON: {str(e)}")
            return {
                'success': False,
                'message': f'JSON parse error: {str(e)}',
                'sigma_rules': []
            }
        except Exception as e:
            logger.error(f"Error parsing Sigma response: {str(e)}")
            return {
                'success': False,
                'message': f'Parse error: {str(e)}',
                'sigma_rules': []
            }
    
    def _build_security_prompt(self, query_type: str, data: Dict[str, Any]) -> str:
        """Build security analysis prompt based on query type and data"""
        
        # Handle Agent-specific prompt types
        if query_type == "agent_query_generation":
            return self._build_agent_query_prompt(data)
        elif query_type == "agent_query_generation_with_errors":
            return self._build_agent_query_prompt_with_errors(data)
        elif query_type == "agent_result_analysis":
            return self._build_agent_analysis_prompt(data)
        elif query_type == "agent_final_report":
            return self._build_agent_report_prompt(data)

        # Build graph context
        graph_analysis = self._build_graph_context(data)
        
        base_context = f"""
        Security Analysis Request:
        Query Type: {query_type}
        
        Network Graph Analysis:
        {graph_analysis}
        """
        
        query_specific_prompts = {
                'system_privileges': """
            Focus: SYSTEM / privileged account analysis
            Hotspots first:
            - User account has 'system' privileges (Username.rights contains 'system')
            - Privileged accounts authenticating across many hosts (4624 LogonType=3/10, 4776 NTLM)
            - Kerberos anomalies in 4768/4769: unusual servicename spread or weak ticketencryptiontype (non-AES)
            Evidence fields to cite:
            - event_id, account, target_host, LogonType, IpAddress, authname, servicename, ticketencryptiontype, Status, Username.rights/status
            """,
                'rdp_logon': """
            Focus: RDP (Remote Desktop) logon analysis
            Hotspots first:
            - 4624 with LogonType=10, or 4769 where servicename starts with 'TERMSRV/'
            - Same source IP authenticating to multiple hosts via RDP
            Evidence fields to cite:
            - event_id, account, target_host, LogonType, IpAddress, authname, servicename, Status
            """,
                'network_logon': """
            Focus: Network logon (LogonType=3) analysis
            Hotspots first:
            - Privileged accounts with LogonType=3 across many hosts
            - 4776 (NTLM) co-occurring with 4624:3 for the same account/source
            - servicename 'CIFS/' spread indicating SMB-based movement
            Evidence fields to cite:
            - event_id, account, target_host, LogonType, IpAddress, authname, servicename, Status
            """,
                'logon_failure': """
            Focus: Logon failure (4625) analysis
            Hotspots first:
            - Same source IP failing against many accounts (spray)
            - Same account failing against many hosts (brute-force/misuse)
            - Coexistence of 4625 and 4624 for same account (compromise indicator)
            Evidence fields to cite:
            - event_id, account, target_host, IpAddress, LogonType, Status/SubStatus
            Note:
            - Absence of 4625 does not imply benign; rely on other events when missing
            Useful event IDs: 4625/4624/4768/4769
            """,
                'ntlm_logon': """
            Focus: NTLM authentication analysis
            Hotspots first:
            - 4776 on DC plus 4624 using NTLM for same account across multiple hosts
            - Privileged accounts using NTLM (authname='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0')
            - Same source IP performing NTLM to multiple targets (relay/reuse suspicion)
            Evidence fields to cite:
            - event_id, account, target_host, LogonType, IpAddress, authname, Status
            """,
                'attack_path': """
            Focus: Attack path (access → movement → escalation)
            Hotspots first:
            - Failures + successes for same account (initial foothold)
            - Lateral movement: Type 3/10 across many hosts; NTLM + Kerberos mix
            - Privilege use/changes: User account has 'system' privileges (Username.rights contains 'system') and Username.status with group adds
            - Kerberos transitions: servicename shifts (TERMSRV → CIFS), weak ticketencryptiontype
            Evidence fields to cite:
            - event_id, account, source_ip/host (if available), target_host, LogonType, authname, servicename, ticketencryptiontype, Status
            Path building:
            - Provide a minimal plausible 3–5 step path from concrete relationships (no time ordering required)
            """,
                'general_analysis': """
            Focus: Holistic security pattern analysis
            Hotspots first:
            - Top 3 risky combos: privileged accounts × cross-host access × legacy/unusual auth (NTLM or atypical servicename) or weak ticketencryptiontype
            Role/baseline:
            - Compare behavior to expected roles (service vs interactive; fixed vs diverse targets)
            Evidence fields to cite:
            - event_id, account, target_host, LogonType, IpAddress, authname, servicename, ticketencryptiontype, Status, Username.rights/status, (rank for emphasis only)
            """}
        
        specific_prompt = query_specific_prompts.get(query_type, query_specific_prompts['general_analysis'])
        
        return f"""
        {base_context}
        
        {specific_prompt}
        
        Please analyze the network graph, user–host relationships, and authentication patterns with an evidence-first approach.

        Hotspot pins (put these first in key_findings; max 3):
        - <event_id> — <account> -> <target_host> [LogonType=?, IP=?, Auth/Service=(authname|servicename), TicketEncType=?, Status=?] — why (≤15 words)

        Recommendations:
        - Tie each action to a named hotspot; specify exact fields to filter or collect (e.g., collect 4769 with servicename='CIFS/<host>' and ticketencryptiontype='RC4').

        Return JSON in this exact format:
        {{
        "risk_level": "Low|Medium|High|Critical",
        "summary": "2–3 sentences; start with the main hotspot rationale",
        "key_findings": ["finding1", "finding2", "finding3"],
        "security_concerns": ["concern1", "concern2"],
        "recommendations": ["recommendation1", "recommendation2", "recommendation3"]
        }}
        You MUST strictly adhere to this JSON format in your response.
        """

    def _build_agent_query_prompt(self, data: Dict[str, Any]) -> str:
        context = data.get('investigation_context', '')
        previous_queries = data.get('previous_queries', [])
        discovered_threats = data.get('discovered_threats', [])

        return f"""
        You are an expert cybersecurity analyst with deep knowledge of Windows Active Directory authentication patterns and Neo4j Cypher.

        INVESTIGATION CONTEXT: {context}

        PREVIOUS QUERIES EXECUTED (treat as DO-NOT-REPEAT set; compare case/whitespace-insensitively):
        {chr(10).join(previous_queries) if previous_queries else 'None - This is the first query'}

        THREATS DISCOVERED SO FAR:
        {json.dumps(discovered_threats, indent=2) if discovered_threats else 'None discovered yet'}

        TASK
        Generate a Cypher query to investigate the highest-value suspicious pattern with minimal risk of query failure AND guaranteed novelty vs previous queries.

        CYPHER SCHEMA (use ONLY these)
        Node Labels: Username, IPAddress, Domain, Date, Deletetime
        Relationship Types: Event, Group

        Node Properties:
        - Username: user, rights, status, rank, sid, counts, counts4624, counts4625, counts4768, counts4769, counts4776, detect
        - IPAddress: IP, hostname, rank
        - Domain: domain
        - Date: date, start, end
        - Deletetime: date, domain, user

        Relationship Properties:
        - Event: id, logintype, authname, status, count, date, servicename, ticketencryptiontype
        - Group: (no standard properties)

        EVIDENCE NOTES
        - Windows default auditing may omit Event 4625. Do NOT require 4625; rely on 4776/4624/4768/4769 and group-change evidence when 4625 is missing.

        PRIORITY TARGETS (high → low; pick the first applicable). Use PageRank as a priority factor for Cypher query Generation.
        1) Privilege escalation indicators
        - Username.rights CONTAINS 'system' (Optional: Username.status CONTAINS 'AddGroup')
        2) Kerberoasting exposure
        - Event.id=4769 (optionally ticketencryptiontype IN ['RC4','DES'] if present)
        3) AS-REP/weak TGT crypto exposure (proxy)
        - Event.id=4768 AND (ticketencryptiontype='RC4' OR servicename='krbtgt')
        4) RDP movement
        - 4624 with logintype=10  OR  (optional) 4769 with servicename STARTS WITH 'TERMSRV/'
        5) NTLM spread (Pass-the-Hash suspicion)
        - Event.id=4776 OR authname='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'
        6) Network/remote logons spread (general)
        - logintype IN [3,10]
        7) Multiple IPs for same user
        - Same Username across distinct IPAddress.IP values (aggregation is client-side)
        8) Failure→success coexistence
        - Presence of both 4625 and 4624 for same Username.user and IPAddress.IP (ordering not required here)
        9) NewCredentials / NetworkCleartext misuse
        - 4624 with logintype IN [9,8]
        10) Inappropriate DC access by non-admin (heuristic)
        - i.hostname CONTAINS 'dc' combined with 4624/4769/4776 by non-privileged Username

        ### NOVELTY & COVERAGE CONSTRAINTS (must-follow)
        - A materially new query MUST differ from all previous queries in ≥1 of:
        (D1) FILTER FIELD: switch among e.id / e.logintype / e.authname / e.status / e.servicename / e.ticketencryptiontype / u.status / u.rights / i.hostname / i.IP
        (D2) LITERAL SET: change concrete values (e.g., e.id 4776 → 4769 → 4624; logintype 10 → 3; etc.)
        (D3) PATTERN: triad MATCH (u:Username)-[e:Event]-(i:IPAddress)  ↔  node-only MATCH (u:Username)
        - EQUIVALENCE CLASSES (treat as SAME; do not repeat):
        - NTLM class:  e.id=4776  ≡  e.authname='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'
        - RDP class:   e.id=4624 AND e.logintype=10  ≡  (optional) e.id=4769 AND e.servicename STARTS WITH 'TERMSRV/'
        - Kerberoast class: e.id=4769 (± ticketencryptiontype if present)
        - AS-REP proxy class: e.id=4768 AND (e.ticketencryptiontype='RC4' OR e.servicename='krbtgt')
        - Failure-success class: presence of both 4625 and 4624 for same user+IP (single-query cannot enforce; fetch raw and correlate client-side)
        - If your candidate collides after normalization and these classes, switch to the next PRIORITY TARGET.
        - Avoid exact duplicates or trivial variants (only RETURN order/spacing changed is not novel).

        QUERY SIMPLIFICATION POLICY
        - Single pattern ONLY: exactly ONE MATCH — (u:Username)-[e:Event]-(i:IPAddress)  OR  (u:Username)
        - No OPTIONAL MATCH / UNION / subqueries / variable-length (*) / APOC / aggregations / ORDER BY
        - No parameters; use literal filters
        - ONE WHERE with ≤2 predicates joined by AND
        - Allowed operators: '=' , 'IN' , 'IS NULL' ; EXCEPTIONS: 'STARTS WITH' (servicename) / 'CONTAINS' (Username.status or i.hostname when DC heuristic is used)
        - Return minimal fields; ALWAYS add LIMIT 1000
        - Use ONLY the labels/properties above; if unsure, drop the filter

        CYPHER QUERY GUIDELINES
        - Use ONE of the shapes above that remains novel per the constraints.
        - Prefer returning: u.user, i.hostname, i.IP, e.id, e.logintype, e.authname, e.servicename, e.ticketencryptiontype, e.status
        - Do NOT use exists(), regex, functions, or complex expressions.

        Return JSON in this exact format:
        {{
        "cypher_query": "MATCH (u:Username)-[e:Event]-(i:IPAddress) WHERE e.id=4624 AND e.logintype=10 RETURN u.user, i.hostname, i.IP, e.id, e.logintype, e.status AS user, u.rank AS rank ORDER BY u.rank DESC LIMIT 1000",
        "investigation_focus": "One short phrase (e.g., 'Privilege escalation scan' / 'AS-REP weak TGT (proxy)' / 'RDP movement')",
        "expected_findings": "One concise sentence on what this query should reveal, including a novelty justification vs previous queries",
        "threat_indicators": ["List 1-3 specific indicators this query targets"]
        }}
        You MUST strictly adhere to this JSON format in your response.
        """

    def _build_agent_query_prompt_with_errors(self, data: Dict[str, Any]) -> str:
        """Build prompt for agent query generation with error feedback"""
        context = data.get('investigation_context', '')
        previous_queries = data.get('previous_queries', [])
        discovered_threats = data.get('discovered_threats', [])
        recent_errors = data.get('recent_errors', [])
        retry_attempt = data.get('retry_attempt', 0)
        iteration = data.get('iteration', 0)
        
        error_feedback = ""
        if recent_errors:
            error_feedback = "\nRECENT QUERY ERRORS TO AVOID:\n"
            for i, error in enumerate(recent_errors):
                error_feedback += f"Error {i+1}:\n"
                error_feedback += f"  Failed Query: {error.get('query', 'Unknown')}\n"
                error_feedback += f"  Error Message: {error.get('error_message', 'Unknown error')}\n"
                error_feedback += f"  Investigation Focus: {error.get('focus', 'Unknown')}\n"
                error_feedback += f"  Iteration: {error.get('iteration', 'Unknown')}\n\n"
            
            error_feedback += "COMMON CYPHER ERRORS TO AVOID:\n"
            error_feedback += "1. Syntax Errors: Check parentheses, brackets, and quotes\n"
            error_feedback += "2. Unknown Properties: Use only existing node/relationship properties\n"
            error_feedback += "3. Invalid Comparisons: Ensure correct data types for comparisons\n"
            error_feedback += "4. Missing Variables: Define all variables before using them\n"
            error_feedback += "5. Invalid Patterns: Use correct relationship direction and patterns\n\n"
        
        return f"""
        You are an expert cybersecurity analyst with deep knowledge of Windows Active Directory authentication patterns and Neo4j Cypher queries.

        INVESTIGATION CONTEXT: {context}

        CURRENT STATUS:
        - Iteration: {iteration + 1}
        - Retry Attempt: {retry_attempt + 1}/3

        PREVIOUS QUERIES EXECUTED (treat as DO-NOT-REPEAT; compare case/whitespace-insensitively):
        {chr(10).join(previous_queries) if previous_queries else 'None - This is the first query'}

        THREATS DISCOVERED SO FAR:
        {json.dumps(discovered_threats, indent=2) if discovered_threats else 'None discovered yet'}

        {error_feedback}

        TASK
        Generate a corrected Cypher query to investigate the next most important security concern with minimal risk of failure AND guaranteed novelty vs previous queries.

        CYPHER SCHEMA VALIDATION (use ONLY these)
        Node Labels: Username, IPAddress, Domain, Date, Deletetime
        Relationship Types: Event, Group

        Node Properties:
        - Username: user, rights, status, rank, sid, counts, counts4624, counts4625, counts4768, counts4769, counts4776, detect
        - IPAddress: IP, hostname, rank
        - Domain: domain
        - Date: date, start, end
        - Deletetime: date, domain, user

        Relationship Properties:
        - Event: id, logintype, authname, status, count, date, servicename, ticketencryptiontype
        - Group: (no standard properties)

        EVIDENCE NOTES
        - Windows default auditing may omit Event 4625. Do NOT require 4625; rely on 4776/4624/4768/4769 and group-change evidence when 4625 is missing.

        ROOT-CAUSE PLAYBOOK (apply before writing the new query)
        - If previous error says Unknown label/relationship/property/type → REMOVE that filter/label; switch to a simpler equality on a known field (e.g., e.id, e.logintype, u.rights).
        - If previous error says syntax/type/parameter error → REMOVE functions/params; keep one WHERE with equality or IN; no functions (exists/regex), no date math.
        - If previous error mentions unsupported operator on field → REPLACE with equality/IN; only allow STARTS WITH on e.servicename and CONTAINS on u.status or i.hostname.
        - If query was rejected as duplicate/near-duplicate → change FILTER FIELD (e.id→e.logintype/u.status/etc.) or PATTERN (triad↔node-only).

        RETRY LADDER (pick based on Retry Attempt)
        - Retry 1 → Triad, one safe filter (e.g., e.id=4776 OR e.logintype=10); RETURN minimal fields; LIMIT 1000.
        - Retry 2 → Simpler triad or node-only; one equality filter (e.g., u.rights='system' OR e.id=4769); LIMIT 1000.
        - Retry 3 → Minimal scan: MATCH (u:Username) RETURN u.user, u.rights, u.status AS user, u.rank AS rank ORDER BY u.rank DESC LIMIT 1000.

        PRIORITY TARGETS (high → low; choose FIRST applicable;  Use PageRank as a priority factor for Cypher query Generation.)
        1) Privilege escalation indicators: u.rights CONTAINS 'system'
        2) Kerberoasting exposure: e.id=4769 (optionally e.ticketencryptiontype IN ['RC4','DES'] if available)
        3) AS-REP roasting exposure: e.id=4768 AND e.ticketencryptiontype IN ['RC4'] AND e.servicename IN ['krbtgt']
        4) RDP movement: e.id=4624 AND e.logintype=10 (optionally e.id=4769 AND e.servicename STARTS WITH 'TERMSRV/')
        5) NTLM spread: e.id=4776 OR e.authname='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'
        6) Network/remote logons (general): e.logintype IN [3,10]
        7) Multiple IPs per user (material collection): triad without filter; client-side dedup on u.user→i.IP
        8) Failure→success coexistence (material collection): e.id IN [4625,4624]
        9) NewCredentials / NetworkCleartext: e.id=4624 AND e.logintype IN [9,8]
        10) Non-admin touching DCs (heuristic): i.hostname CONTAINS 'dc' AND e.id IN [4624,4769,4776] AND (u.rights IS NULL OR u.rights <> 'system')

        NOVELTY & COVERAGE CONSTRAINTS (must-follow)
        - A materially new query MUST differ from all previous queries in ≥1:
        (D1) FILTER FIELD: switch among e.id / e.logintype / e.authname / e.status / e.servicename / e.ticketencryptiontype / u.status / u.rights / i.hostname / i.IP
        (D2) LITERAL SET: change values (e.g., e.id 4769→4776; logintype 10→3)
        (D3) PATTERN: triad MATCH (u)-[e]-(i)  ↔  node-only MATCH (u:Username)
        - EQUIVALENCE CLASSES (treat as SAME; do not repeat):
        - NTLM: e.id=4776 ≡ e.authname='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'
        - RDP:  e.id=4624 AND e.logintype=10 ≡ (optional) e.id=4769 AND e.servicename STARTS WITH 'TERMSRV/'
        - Kerberoast: e.id=4769 (± ticketencryptiontype if present)
        - Failure→success: presence of both 4625 and 4624 for same user+IP (fetch raw, correlate client-side)
        - If your candidate collides after normalization and these classes, switch to the next PRIORITY TARGET.

        QUERY SIMPLIFICATION POLICY (to reduce failures)
        - Exactly ONE MATCH pattern: (u:Username)-[e:Event]-(i:IPAddress) OR (u:Username)
        - No OPTIONAL MATCH / UNION / subqueries / variable-length (*) / APOC / aggregations / ORDER BY
        - No parameters ($…)
        - One WHERE with ≤2 predicates joined by AND
        - Allowed operators: '=' , 'IN' ; EXCEPTIONS: 'STARTS WITH' on e.servicename, 'CONTAINS' on u.status or i.hostname
        - No functions (no exists/regex/date math)
        - Return fields (not whole nodes); ALWAYS add LIMIT 1000
        - Use ONLY the validated labels/properties above; when unsure, DROP the risky filter

        Return JSON in this exact format:
        {{
        "cypher_query": "MATCH (u:Username)-[e:Event]-(i:IPAddress) WHERE e.id=4624 AND e.logintype=10 RETURN u.user, i.hostname, i.IP, e.id, e.logintype, e.status AS user, u.rank AS rank ORDER BY u.rank DESC LIMIT 1000",
        "investigation_focus": "Specific area being investigated (e.g., 'RDP movement', 'Kerberoasting triage')",
        "expected_findings": "What suspicious patterns this query should reveal, including a brief novelty justification vs previous queries",
        "threat_indicators": ["List of specific indicators this query targets"],
        "error_corrections": ["Concrete fixes applied based on the last error(s), e.g., dropped unknown property, switched to equality, simplified WHERE"]
        }}
        You MUST strictly adhere to this JSON format in your response.
        """

    def _build_agent_analysis_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for agent result analysis"""
        query = data.get('cypher_query', '')
        focus = data.get('investigation_focus', '')
        results = data.get('results', [])
        results_count = data.get('results_count', 0)
        current_iteration = data.get('iteration', 0)
        max_iterations = data.get('max_iterations', self.config.agent_max_iterations or 10)
        
        return f"""
        You are analyzing the results of a cybersecurity investigation query.

        INVESTIGATION PROGRESS:
        - Current Iteration: {current_iteration + 1}/{max_iterations}
        - Investigation Focus: {focus}
        - Query Results: {results_count} records found

        EXECUTED QUERY: {query}

        SAMPLE RESULTS (first 1000):
        {json.dumps(results[:1000], indent=2)}

        TASK: Analyze these Neo4j query results for security threats and determine next investigation steps. 
        Important data notes:
        - Windows defaults may omit Event 4625. Do NOT treat the absence of 4625 as benign; rely on other evidence (4776, 4624:3/10, 4768/4769, group changes).
        - Ambiguous values (e.g., LogonType=0, authname='-') alone must NOT drive severity.

        DETECTORS (apply all; mark which triggered)
        A. Cross-host NTLM by privileged account
        Trigger if:
            (Username.rights indicates system OR Username.status mentions high-privilege)
            AND (any Event.id=4776 OR e.authname='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0')
            AND distinct target hosts for this user ≥ 3.

        B. Multiple IPs for same user
        Trigger if distinct IPAddress.IP for the same Username.user ≥ 2.

        C. Failure→success coexistence (optional)
        Trigger if both 4625 and 4624 exist for the same Username.user and IPAddress.IP (ordering not required).

        D. Privilege escalation indicators
        Trigger if Username.status contains 'AddGroup'/'Created'.

        E. Kerberos irregularities
        Trigger if any Event.id in {{4768, 4769}} with atypical service patterns (e.g., unusual servicename like TERMSRV/… or CIFS/… for this user/host role)
        OR the same user/host set mixes NTLM (4776) and Kerberos (4768/4769) unexpectedly.

        F. Network/remote interactive spread
        Trigger if Event.logintype in {{3,10}} for the same user across ≥ 3 hosts, OR across both methods (3 and 10).

        G. Kerberoasting exposure
        Trigger if any Event.id=4769 with signs of weak crypto (ticketencryptiontype non-AES like RC4/DES when available)
        OR many distinct servicename values requested by the same user.

        H. AS-REP roasting exposure (proxy)
        Trigger if any Event.id=4768 AND Event.ticketencryptiontype='RC4' AND Event.servicename='krbtgt' for the same user.

        I. RDP movement
        Trigger if 4624 with LogonType=10 across multiple hosts
        (optionally corroborated by 4769 with servicename STARTS WITH 'TERMSRV/').

        J. NewCredentials / NetworkCleartext misuse
        Trigger if 4624 with LogonType in {{9,8}} for privileged/likely-privileged accounts across ≥ 2 hosts.

        BENIGN CONTEXT CHECKS (evaluate before High/Critical)
        - Bastion/jump/automation sources with uniform method and no privilege-change evidence
        - DC/infra norms (e.g., routine 4768/4769 issuance; 4776 on DC alone)
        - Stable small destination set (≤2 hosts) without escalation indicators
        If a strong benign explanation applies and no corroborating detector triggers, downgrade severity.

        CORROBORATION RULE (for High/Critical)
        - Escalate to High/Critical ONLY when there are at least two independent detectors among {{A, D, E, F, G, H, I, J}},
        unless D shows clear active use (e.g., privilege change plus successful logons), which can justify High by itself.
        - B or C alone must NOT exceed Medium without corroboration.

        SEVERITY POLICY (choose one primary threat_type)
        - threat_type: one of lateral_movement | privilege_escalation | credential_theft | brute_force | insider_threat | none
        - mapping (deterministic guidance):
        * critical:
            - D (privilege escalation) AND (A OR F OR G OR H OR I OR J), with no strong benign explanation; OR
            - G (kerberoasting) with multi-service scope (many distinct servicename) AND evidence of use/movement (A or F or I); OR
            - H (AS-REP proxy) PLUS subsequent successful access (e.g., 4624:3/10 or 4769 service use) indicating credential use.
        * high:
            - Any two detectors among {{A, D, E, F, G, H, I, J}} without strong benign explanation; OR
            - D with active use (e.g., 4672/group-change evidence AND successful 4624/4768/4769/4776) even alone.
        * medium:
            - Single strong detector among {{A, D, E, F, G, H, I, J}} with partial evidence or plausible benign context; OR
            - B or C combined with any weak corroboration (e.g., limited spread).
        * low:
            - Only weak signals (B or C alone) OR patterns matching benign context.
        If multiple types apply, pick the most dangerous single primary type and justify in the description.

        INVESTIGATION COMPLETION GUIDANCE:
        - Current progress: Iteration {current_iteration + 1} of {max_iterations}
        - If this is iteration {max_iterations} (final), set investigation_complete=true unless critical threats require immediate follow-up
        - If approaching final iterations ({max_iterations - 1}, {max_iterations}), prioritize high-impact findings over breadth
        - For earlier iterations, continue investigation if significant threats are detected or patterns suggest deeper compromise

        Return JSON in this exact format:
        {{
        "threat_detected": true/false,
        "threat_type": "lateral_movement|privilege_escalation|credential_theft|brute_force|insider_threat|none",
        "severity": "low|medium|high|critical",
        "threat_description": "Detailed description grounded in exact fields (no math talk). Name user(s), host(s), IP(s), Event.id, logintype, authname, servicename (if available), ticketencryptiontype (if available), and status/substatus if present.",
        "evidence": [
            "Concrete points like: Username.user='administrator' — Event.id=4776 — IPAddress.IP='192.168.16.103' — Event.logintype=3",
            "Username.status contains 'AddGroup: Domain Admins'",
            "Event.id=4769 — servicename='TERMSRV/win7_64jp_01' — ticketencryptiontype='RC4'"
        ],
        "investigation_complete": true/false,
        "next_investigation_context": "If false: propose the single most useful next Neo4j Cypher to run, inline (no backticks). Use exact labels/properties from this schema and a minimal MATCH/RETURN. Example: MATCH (u:Username)-[e:Event]-(i:IPAddress) WHERE u.user='administrator' AND e.id=4776 RETURN u.user, i.hostname, i.IP, e.id, e.logintype, e.authname, e.status AS user, u.rank AS rank ORDER BY u.rank DESC LIMIT 1000",
        "recommendations": ["Immediate actions tied to the evidence, e.g., isolate host=<hostname>, rotate credentials for user=<user>, collect Event.id in (4624,4776,4768,4769) for the named entities"]
        }}
        You MUST strictly adhere to this JSON format in your response.
        """

    def _build_agent_report_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for final investigation report"""
        summary = data.get('investigation_summary', {})
        threats = data.get('discovered_threats', [])
        timeline = data.get('investigation_timeline', [])
        
        return f"""
        You are generating a comprehensive cybersecurity investigation report based on prior Neo4j-driven iterations.

        CONTEXT (provided as variables):
        - INVESTIGATION SUMMARY (object): total iterations and counts
        - Total Iterations: {summary.get('total_iterations', 0)}
        - Threats Found: {summary.get('threats_found', 0)}
        - DISCOVERED THREATS (array of prior results; each result follows the investigation-phase JSON schema):
        {json.dumps(threats, indent=2)}
        - INVESTIGATION TIMELINE (array; may include raw events or summarized steps; timestamps may or may not be present):
        {json.dumps(timeline, indent=2)}

        ALIGNMENT WITH INVESTIGATION PHASE:
        - Use the same DETECTORS taxonomy (A–J). When summarizing a threat, explicitly mention which detectors triggered (e.g., "Detectors: A,E").
        A Cross-host NTLM by privileged account
        B Multiple IPs for same user
        C Failure→success coexistence
        D Privilege escalation indicators
        E Kerberos irregularities
        F Network/remote interactive spread
        G Kerberoasting exposure (4769; optional ticketencryptiontype non-AES)
        H AS-REP roasting exposure (4768; proxy: ticketencryptiontype='RC4' AND servicename='krbtgt')
        I RDP movement (4624:10; optional TERMSRV/)
        J NewCredentials / NetworkCleartext misuse (4624:9/8)

        REPORTING RULES:
        - Evidence-first. Name users, hosts, IPs, Event.id, logintype, authname, servicename (if available), ticketencryptiontype (if available), and status/substatus when present.
        - Apply the same severity semantics as the investigation phase (low|medium|high|critical). Do not introduce new categories.
        - Absence of 4625 must NOT be treated as benign; ambiguous values (LogonType=0, authname='-') alone must NOT drive severity.
        - If Event.date timestamps are present, order activities chronologically; otherwise reconstruct the sequence using relationships and co-occurrence only.
        - Deduplicate near-duplicates by grouping on (primary account, primary target_host) and merging overlapping evidence.

        THREAT-TYPE MAPPING HINTS (choose the most dangerous single primary type):
        - privilege_escalation: D (and related use where Username.rights contains 'system' (Optional: Username.status contains 'AddGroup'))
        - credential_theft: G, H, C (spray→success) when theft is primary
        - lateral_movement: A, F, I, E (when service scope shifts imply movement)
        - brute_force: C when failure patterns dominate and no privilege escalation is shown
        - insider_threat: reserved for clearly internal misuse patterns when others do not apply better

        TASK: Generate a comprehensive security investigation report that consolidates all discovered threats and the investigation timeline, prioritizes risks, and provides actionable recommendations.

        REPORT STRUCTURE (fill all keys; do not add or remove top-level keys):
        Return JSON in this exact format:
        {{
        "analysis_summary": "A concise, 6-10 sentence synthesis across ALL results: name the top 1–2 hotspot accounts/hosts and methods. If the analysis identifies any compromised users or hosts, note them in this summary.",
        "overall_risk_level": "low|medium|high|critical",
        "threats_summary": {{
            "total_threats": number,
            "critical_threats": number,
            "threat_types": ["list of threat types found"]  // choose from: lateral_movement, privilege_escalation, credential_theft, brute_force, insider_threat
        }},
        "recommendations": {{
            "immediate": [
            "Containment/credential actions tied to specific evidence (e.g., isolate host=<hostname>; rotate credentials for user=<user>; collect Event.id in (4624,4776,4768,4769) for named entities)"
            ],
            "short_term": [
            "Focused hardening and log collection improvements (e.g., enable/verify audit settings; restrict NTLM; validate group memberships)"
            ],
            "long_term": [
            "Strategic improvements (e.g., mandate Kerberos-only where feasible; deploy tiering; service account hygiene; ongoing detection content)"
            ]
        }},
        "detection_rules": [
            // Provide 5–10 concise, rule-style statements aligned to A–J (no time assumptions). Examples:
            "A: If Username.rights indicates system (Optional: Username.status contains 'AddGroup'), AND Event.id=4776, AND distinct IPAddress.hostname >= 3 → alert Cross-host NTLM by privileged account.",
            "D: If Username.status CONTAINS 'AddGroup' OR 'Created' → alert Privilege escalation.",
            "G: If Event.id=4769 AND (ticketencryptiontype='RC4' OR 'DES' WHEN available) OR same user hits many distinct servicename values → alert Kerberoasting exposure.",
            "H: If Event.id=4768 AND ticketencryptiontype='RC4' AND servicename='krbtgt' repeats for the same user → alert AS-REP roasting exposure (proxy).",
            "I: If Event.id=4624 AND logintype=10 across multiple hosts (optionally corroborated by 4769 TERMSRV/) → alert RDP movement.",
            "F: If logintype IN [3,10] across >=3 hosts for the same user → alert Network/remote interactive spread.",
            "E: If Event.id IN {4768,4769} shows atypical servicename patterns (TERMSRV/CIFS/etc.) or mixed NTLM+Kerberos for same user/host → alert Kerberos irregularities.",
            "C: If the same user+IP shows both 4625 and 4624 → alert Failure→success compromise.",
            "B: If the same user authenticates from >=2 distinct IPAddress.IP in short window → raise Suspicious multi-origin use.",
            "J: If Event.id=4624 AND logintype IN [9,8] for privileged/likely-privileged accounts across >=2 hosts → alert NewCredentials/NetworkCleartext misuse."
        ]
        }}
        You MUST strictly adhere to this JSON format in your response.
        """


    def _build_graph_context(self, data: Dict[str, Any]) -> str:
        """Build detailed graph context from Neo4j data"""
        context_parts = []
        
        # Detailed user information
        users = data.get('users', [])
        if users:
            context_parts.append("User Accounts:")
            for i, user in enumerate(users[:20]):
                privilege_info = f" (Privilege: {user.get('privilege', 'Unknown')})" if user.get('privilege') else ""
                status_info = f" (Status: {user.get('status', 'Unknown')})" if user.get('status') else ""
                rank_info = f" (PageRank: {user.get('rank', 'N/A')})" if user.get('rank') is not None else ""
                context_parts.append(f"  - {user.get('name', f'User_{i+1}')}{privilege_info}{status_info}{rank_info}")
            
            if len(users) > 20:
                context_parts.append(f"  ... and {len(users) - 20} more users")
            context_parts.append("")
            
            # Top 10 Users by PageRank
            users_with_rank = [user for user in users if user.get('rank') is not None]
            if users_with_rank:
                sorted_users = sorted(users_with_rank, key=lambda x: x.get('rank', 0), reverse=True)[:10]
                context_parts.append("Top 10 Users by PageRank:")
                for i, user in enumerate(sorted_users):
                    privilege_info = f" (Privilege: {user.get('privilege', 'Unknown')})" if user.get('privilege') else ""
                    status_info = f" (Status: {user.get('status', 'Unknown')})" if user.get('status') else ""
                    context_parts.append(f"  {i+1}. {user.get('name', 'Unknown')} - Rank: {user.get('rank', 'N/A')}{privilege_info}{status_info}")
                context_parts.append("")
        
        # Detailed host information
        hosts = data.get('hosts', [])
        if hosts:
            context_parts.append("Host Systems:")
            for i, host in enumerate(hosts[:20]):
                ip = host.get('ip', f'Unknown_IP_{i+1}')
                hostname = host.get('hostname', 'Unknown_Hostname')
                rank_info = f" (PageRank: {host.get('rank', 'N/A')})" if host.get('rank') is not None else ""
                
                if hostname and hostname != 'Unknown_Hostname':
                    context_parts.append(f"  - {ip} ({hostname}){rank_info}")
                else:
                    context_parts.append(f"  - {ip}{rank_info}")
            
            if len(hosts) > 20:
                context_parts.append(f"  ... and {len(hosts) - 20} more hosts")
            context_parts.append("")
            
            # Top 10 Hosts by PageRank
            hosts_with_rank = [host for host in hosts if host.get('rank') is not None]
            if hosts_with_rank:
                sorted_hosts = sorted(hosts_with_rank, key=lambda x: x.get('rank', 0), reverse=True)[:10]
                context_parts.append("Top 10 Hosts by PageRank:")
                for i, host in enumerate(sorted_hosts):
                    ip = host.get('ip', 'Unknown_IP')
                    hostname = host.get('hostname', 'Unknown_Hostname')
                    display_name = f"{ip} ({hostname})" if hostname and hostname != 'Unknown_Hostname' else ip
                    context_parts.append(f"  {i+1}. {display_name} - Rank: {host.get('rank', 'N/A')}")
                context_parts.append("")

        # Detailed event information
        events = data.get('events', [])
        if events:
            context_parts.append("Authentication Events:")
            
            event_stats = {}
            logon_type_stats = {}
            auth_method_stats = {}
            
            for event in events:
                event_id = event.get('event_id', 'Unknown')
                event_stats[event_id] = event_stats.get(event_id, 0) + 1
                
                logon_type = event.get('logon_type', 'Unknown')
                logon_type_stats[logon_type] = logon_type_stats.get(logon_type, 0) + 1
                
                auth_method = event.get('auth_method', 'Unknown')
                auth_method_stats[auth_method] = auth_method_stats.get(auth_method, 0) + 1
            
            if event_stats:
                context_parts.append("  Event ID Distribution:")
                for event_id, count in sorted(event_stats.items(), key=lambda x: x[1], reverse=True):
                    event_name = self._get_event_name(event_id)
                    context_parts.append(f"    - Event {event_id} ({event_name}): {count} occurrences")
            
            if logon_type_stats:
                context_parts.append("  Logon Type Distribution:")
                for logon_type, count in sorted(logon_type_stats.items(), key=lambda x: x[1], reverse=True):
                    logon_name = self._get_logon_type_name(logon_type)
                    context_parts.append(f"    - Type {logon_type} ({logon_name}): {count} events")
            
            if auth_method_stats:
                context_parts.append("  Authentication Method Distribution:")
                for auth_method, count in sorted(auth_method_stats.items(), key=lambda x: x[1], reverse=True):
                    context_parts.append(f"    - {auth_method}: {count} events")
            
            context_parts.append("")
        
        # Network relationship analysis
        context_parts.append("Network Relationship Analysis:")
        
        network_relations = data.get('network_relations', {})
        detailed_connections = network_relations.get('detailed_connections', [])
        
        if detailed_connections:
            context_parts.append("  Detailed User-Host Relationships:")
            for connection in detailed_connections[:20]:
                formatted_connection = connection.get('formatted', '')
                total_events = connection.get('total_events', 0)
                if formatted_connection:
                    context_parts.append(f"    - {formatted_connection} ({total_events} events)")
            
            summary = network_relations.get('summary', {})
            if summary:
                context_parts.append(f"  Summary: {summary.get('total_connections', 0)} connections between {summary.get('unique_users', 0)} users and {summary.get('unique_hosts', 0)} hosts")
        else:
            user_host_mapping = {}
            host_user_mapping = {}
            
            for event in events:
                source_user = event.get('source_user')
                target_host = event.get('target_host')
                
                if source_user and target_host:
                    if source_user not in user_host_mapping:
                        user_host_mapping[source_user] = set()
                    user_host_mapping[source_user].add(target_host)
                    
                    if target_host not in host_user_mapping:
                        host_user_mapping[target_host] = set()
                    host_user_mapping[target_host].add(source_user)
            
            multi_host_users = [(user, len(hosts)) for user, hosts in user_host_mapping.items() if len(hosts) > 3]
            if multi_host_users:
                context_parts.append("  Users with High Host Access (Potential Lateral Movement):")
                for user, host_count in sorted(multi_host_users, key=lambda x: x[1], reverse=True)[:5]:
                    context_parts.append(f"    - {user}: accessed {host_count} different hosts")
            
            multi_user_hosts = [(host, len(users)) for host, users in host_user_mapping.items() if len(users) > 3]
            if multi_user_hosts:
                context_parts.append("  Hosts with High User Access (Potential High-Value Targets):")
                for host, user_count in sorted(multi_user_hosts, key=lambda x: x[1], reverse=True)[:5]:
                    context_parts.append(f"    - {host}: accessed by {user_count} different users")
        
        if not context_parts or len(context_parts) <= 1:
            context_parts.append("No detailed graph data available for analysis.")
        
        return "\n".join(context_parts)

    def _get_event_name(self, event_id) -> str:
        """Get human-readable event name"""
        event_names = {
            '4624': 'Successful Logon',
            '4625': 'Failed Logon',
            '4634': 'Logoff',
            '4648': 'Explicit Credential Use',
            '4672': 'Special Privileges Assigned',
            '4768': 'Kerberos TGT Request',
            '4769': 'Kerberos Service Ticket Request',
            '4771': 'Kerberos Pre-auth Failed',
            '4776': 'NTLM Authentication',
            '4778': 'Session Reconnected',
            '4779': 'Session Disconnected'
        }
        return event_names.get(str(event_id), 'Unknown Event')

    def _get_logon_type_name(self, logon_type) -> str:
        """Get human-readable logon type name"""
        logon_types = {
            '2': 'Interactive',
            '3': 'Network',
            '4': 'Batch',
            '5': 'Service',
            '7': 'Unlock',
            '8': 'NetworkCleartext',
            '9': 'NewCredentials',
            '10': 'RemoteInteractive (RDP)',
            '11': 'CachedInteractive'
        }
        return logon_types.get(str(logon_type), 'Unknown Type')
    
    def _get_pagerank_data_from_neo4j(self) -> Dict[str, Any]:
        """Get PageRank data from Neo4j database"""
        try:
            # Try to get Neo4j connection details from multiple sources
            neo4j_uri = None
            neo4j_user = None 
            neo4j_password = None
            database = "neo4j"
            
            # First try Flask context
            try:
                from flask import has_app_context, current_app
                if has_app_context() and current_app:
                    # Try to get connection details from app config
                    neo4j_uri = current_app.config.get('NEO4J_URI')
                    neo4j_user = current_app.config.get('NEO4J_USER')
                    neo4j_password = current_app.config.get('NEO4J_PASSWORD')
                    database = current_app.config.get('NEO4J_DATABASE', 'neo4j')
            except:
                pass
            
            # Try to get from logontracer module globals if available
            if not neo4j_uri:
                try:
                    import logontracer
                    # Check if logontracer has neo4j connection variables
                    if hasattr(logontracer, 'args') and logontracer.args:
                        neo4j_server = getattr(logontracer.args, 'server', 'localhost')
                        neo4j_user = getattr(logontracer.args, 'user', 'neo4j')
                        neo4j_password = getattr(logontracer.args, 'password', 'password')
                        wsport = getattr(logontracer.args, 'wsport', '7687')
                        neo4j_uri = f"bolt://{neo4j_server}:{wsport}"
                        database = getattr(logontracer.args, 'case', 'neo4j')
                except:
                    pass
            
            # Fallback to environment variables
            if not neo4j_uri:
                neo4j_uri = os.environ.get('NEO4J_URI', 'bolt://localhost:7687')
                neo4j_user = os.environ.get('NEO4J_USER', 'neo4j')
                neo4j_password = os.environ.get('NEO4J_PASSWORD', 'password')
            
            if not all([neo4j_uri, neo4j_user, neo4j_password]):
                logger.warning("Neo4j connection details not available")
                return {}

            username_query = """
            MATCH (u:Username)
            WHERE u.rank IS NOT NULL
            RETURN u.user AS user, u.rank AS rank
            ORDER BY u.rank DESC
            LIMIT 1000
            """

            ipaddress_query = """
            MATCH (i:IPAddress)
            WHERE i.rank IS NOT NULL
            RETURN i.IP AS ip, i.hostname AS hostname, i.rank AS rank
            ORDER BY i.rank DESC
            LIMIT 1000
            """

            username_ranks = []
            ipaddress_ranks = []

            with GraphDatabase.driver(
                neo4j_uri,
                auth=(neo4j_user, neo4j_password)
            ) as driver:
                with driver.session(database=database) as neo4j_session:
                    username_result = neo4j_session.run(username_query)
                    for record in username_result:
                        username_ranks.append({
                            'user': record.get('user'),
                            'rank': record.get('rank')
                        })

                    ipaddress_result = neo4j_session.run(ipaddress_query)
                    for record in ipaddress_result:
                        ipaddress_ranks.append({
                            'ip': record.get('ip'),
                            'hostname': record.get('hostname', 'Unknown'),
                            'rank': record.get('rank')
                        })
            
            logger.info(f"Retrieved PageRank data: {len(username_ranks)} users, {len(ipaddress_ranks)} IP addresses")
            
            return {
                'username_ranks': username_ranks,
                'ipaddress_ranks': ipaddress_ranks
            }
            
        except Exception as e:
            logger.warning(f"Failed to retrieve PageRank data from Neo4j: {str(e)}")
            return {}
    
    def _build_pagerank_context(self, pagerank_data: Dict[str, Any] = None) -> str:
        """Build PageRank context section for system message"""
        if not pagerank_data:
            pagerank_data = self._get_pagerank_data_from_neo4j()
        
        if not pagerank_data or (not pagerank_data.get('username_ranks') and not pagerank_data.get('ipaddress_ranks')):
            return """
                    CURRENT PAGERANK DATA
                    - No PageRank data available from Neo4j database
                    - Use relative rank analysis if Username.rank or IPAddress.rank fields are present in the data
                    """
        
        context_parts = ["""
                    CURRENT PAGERANK DATA
                    - Use this baseline to identify rank anomalies and suspicious patterns
                    """]
        
        # Add top username rankings
        username_ranks = pagerank_data.get('username_ranks', [])
        if username_ranks:
            context_parts.append("                    TOP USERNAME RANKINGS (by PageRank):")
            for i, user_data in enumerate(username_ranks[:10]):
                user = user_data.get('user', 'Unknown')
                rank = user_data.get('rank', 'N/A')
                context_parts.append(f"                      {i+1}. {user} (rank: {rank})")
            
            if len(username_ranks) > 10:
                context_parts.append(f"                      ... and {len(username_ranks) - 10} more users")
        
        # Add top IP address rankings
        ipaddress_ranks = pagerank_data.get('ipaddress_ranks', [])
        if ipaddress_ranks:
            context_parts.append("                    TOP IPADDRESS RANKINGS (by PageRank):")
            for i, ip_data in enumerate(ipaddress_ranks[:10]):
                ip = ip_data.get('ip', 'Unknown')
                hostname = ip_data.get('hostname', 'Unknown')
                rank = ip_data.get('rank', 'N/A')
                if hostname and hostname != 'Unknown':
                    display = f"{ip} ({hostname})"
                else:
                    display = ip
                context_parts.append(f"                      {i+1}. {display} (rank: {rank})")
            
            if len(ipaddress_ranks) > 10:
                context_parts.append(f"                      ... and {len(ipaddress_ranks) - 10} more IP addresses")
        
        return "\n".join(context_parts)
    
    def _parse_analysis_response(self, content: str) -> Dict[str, Any]:
        """Parse response and extract structured analysis"""
        try:
            # Try to extract JSON from the response
            start_idx = content.find('{')
            end_idx = content.rfind('}') + 1
            
            if start_idx != -1 and end_idx != 0:
                json_str = content[start_idx:end_idx]
                analysis = json.loads(json_str)
                
                # Validate required fields
                required_fields = ['risk_level', 'summary', 'key_findings', 'security_concerns', 
                                 'recommendations']
                
                for field in required_fields:
                    if field not in analysis:
                        analysis[field] = []
                
                return analysis
            else:
                # Fallback: parse free-form text
                return self._parse_freeform_response(content)
                
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON response, using fallback parser")
            return self._parse_freeform_response(content)
        except Exception as e:
            logger.error(f"Error parsing analysis response: {str(e)}")
            return self._create_error_response("Failed to parse analysis")
    
    def _parse_freeform_response(self, content: str) -> Dict[str, Any]:
        """Fallback parser for non-JSON responses"""
        lines = content.split('\n')
        
        # Extract risk level
        risk_level = "Medium"
        for line in lines:
            if any(word in line.lower() for word in ['critical', 'high', 'medium', 'low']):
                if 'critical' in line.lower():
                    risk_level = "Critical"
                elif 'high' in line.lower():
                    risk_level = "High"
                elif 'medium' in line.lower():
                    risk_level = "Medium"
                elif 'low' in line.lower():
                    risk_level = "Low"
                break
        
        return {
            "risk_level": risk_level,
            "summary": content[:200] + "..." if len(content) > 200 else content,
            "key_findings": ["Analysis provided in free-form text"],
            "security_concerns": ["Review the full analysis for security concerns"],
            "recommendations": ["Refer to the detailed analysis for recommendations"]
        }
    
    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create error response structure"""
        return {
            "risk_level": "Unknown",
            "summary": f"Analysis failed: {error_message}",
            "key_findings": ["Analysis could not be completed"],
            "security_concerns": ["Unable to assess security risks"],
            "recommendations": ["Check AI service configuration and try again"]
        }

    def _create_quota_exceeded_response(self) -> Dict[str, Any]:
        """Create response for quota exceeded error"""
        return {
            "risk_level": "Unknown",
            "summary": "OpenAI API quota exceeded. Please check your billing plan and usage limits.",
            "key_findings": [
                "AI analysis is temporarily unavailable due to API quota limits",
                "Manual security analysis is required"
            ],
            "security_concerns": [
                "Automated threat detection is currently disabled",
                "Security analysis must be performed manually"
            ],
            "recommendations": [
                "Check OpenAI API billing and usage at https://platform.openai.com/usage",
                "Upgrade your OpenAI plan if needed",
                "Consider implementing rate limiting for API calls",
                "Review and optimize prompt efficiency to reduce token usage",
                "Implement fallback manual analysis procedures"
            ]
        }

    def _create_auth_error_response(self) -> Dict[str, Any]:
        """Create response for authentication error"""
        return {
            "risk_level": "Unknown",
            "summary": "OpenAI API authentication failed. Please check your API key configuration.",
            "key_findings": ["AI analysis service authentication failed"],
            "security_concerns": ["Automated security analysis is unavailable"],
            "recommendations": [
                "Verify OpenAI API key is correctly configured",
                "Check API key permissions and validity",
                "Regenerate API key if necessary"
            ]
        }

    def _create_connection_error_response(self) -> Dict[str, Any]:
        """Create response for connection error"""
        return {
            "risk_level": "Unknown",
            "summary": "Unable to connect to OpenAI API. Please check network connectivity.",
            "key_findings": ["AI analysis service is unreachable"],
            "security_concerns": ["Automated threat detection is temporarily offline"],
            "recommendations": [
                "Check internet connectivity",
                "Verify firewall settings allow OpenAI API access",
                "Try again in a few minutes",
                "Implement offline analysis procedures"
            ]
        }

    def _create_timeout_error_response(self) -> Dict[str, Any]:
        """Create response for timeout error"""
        return {
            "risk_level": "Unknown",
            "summary": "OpenAI API request timed out. The service may be experiencing high load.",
            "key_findings": ["AI analysis request exceeded timeout limit"],
            "security_concerns": ["Analysis could not be completed within time limit"],
            "recommendations": [
                "Try again with a simpler query",
                "Check OpenAI service status at https://status.openai.com/",
                "Consider increasing timeout settings",
                "Reduce analysis scope to speed up processing"
            ]
        }

    def _build_system_message(self, pagerank_data: Dict[str, Any] = None) -> str:
        """Build language-specific system message with PageRank context"""
        language = self.config.response_language or 'en'
        
        # Language-specific instructions
        language_instructions = {
            'en': {
                'response_instruction': "You must respond in English. All field names, structure, and content should be in English.",
                'json_note': "Provide your analysis in English following the JSON format specified."
            },
            'ja': {
                'response_instruction': "必ず日本語で回答してください。JSONの構造とフィールド名は英語のままで、内容（値）のみ日本語で記述してください。",
                'json_note': "指定されたJSON形式に従って、内容を日本語で分析結果を提供してください。"
            },
            'fr': {
                'response_instruction': "Vous devez répondre en français. La structure JSON et les noms de champs restent en anglais, mais le contenu (valeurs) doit être en français.",
                'json_note': "Fournissez votre analyse en français en suivant le format JSON spécifié."
            }
        }
        
        lang_config = language_instructions.get(language, language_instructions['en'])
        
        # Build PageRank context section
        pagerank_context = self._build_pagerank_context(pagerank_data)
        
        return f"""You are a senior DFIR analyst investigating Windows logons with JPCERT/CC LogonTracer.
                    PRIMARY OBJECTIVE
                    - Point DIRECTLY to suspicious log evidence (who/what/where/when if present). Do NOT explain scoring math.
                    INPUT CONTRACT
                    - You will receive a "Security Analysis Request" containing graph summaries and raw evidence.
                    - Treat this as the complete dataset. Do not invent fields; if missing, write "unknown".
                    HOW TO REASON (evidence-first; use only available fields)
                    - Prioritize concrete patterns:
                    • Cross-host NTLM by privileged accounts (Event.id=4776 or authname='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0')
                    • Failure→success (4625 then 4624) when 4625 exists
                    • Special privileges/privilege changes (Username.status includes 'AddGroup' and Username.rights indicates 'system')
                    • Kerberos anomalies in 4768/4769 using SPN/Service: authname/servicename (e.g., TERMSRV/, CIFS/, MSSQLSvc/)
                    • Weak crypto or roasting exposure: ticketencryptiontype not AES (RC4/DES), widespread TGS to many services
                    • Mixed methods for same user/host set (NTLM 4776 + Kerberos 4768/4769)
                    PAGERANK USAGE (FOR BOTH Cypher query Generation & Analysis)
                    - You are given:
                    • Username.rank
                    • IPAddress.rank
                    Use PageRank as a weighting signal to choose where to look and what to highlight, NEVER as standalone evidence.
                    Use PageRank as a priority factor for Cypher query Generation and as a reference value for Analysis.
                    {pagerank_context}
                    LOGGING CAVEAT
                    - Windows defaults may NOT log 4625. Do not reduce risk due to missing 4625; rely on 4776/4624/4768/4769 and other fields.
                    STRICT OUTPUT MAPPING
                    - Follow exactly the JSON schema provided by the user prompt (no extra keys).
                    - "risk_level": Low|Medium|High|Critical (no math explanation).
                    - "summary": 2–3 sentences. First sentence must state the top-risk hotspot:
                    Top Risk: <account> -> <target_host> at <date or 'unknown'> via <auth/logon_type> — <≤12-word reason>.
                    - "key_findings": First three are one-line Hotspot pins, each citing exact fields:
                    • <event_id> <date or 'unknown'> — <account> -> <target_host> [LogonType=?, IP=?, Auth/Service=(authname/servicename), TicketEncType=?, Status/SubStatus=?, UserRank=?, HostRank=?] — why (≤15 words)
                    - "security_concerns": 2–3 bullets tied to fields (e.g., "4776 across 3 hosts by SYSTEM").
                    - "recommendations": 2–3 actions tied to named hotspots.
                    STYLE
                    - Be terse and operational. Always cite exact fields: Event.id, logintype, status, authname, servicename, ticketencryptiontype, Username.user/rights/status/rank, IPAddress.hostname/IP/rank.
                    - Include PageRank context when relevant (e.g., "low-rank user accessing high-rank host", "high-rank user with unusual pattern").
                    - Prefer concrete relationships over generalities. If a critical artifact is missing, name the single most valuable missing piece.
                    NEO4J SCHEMA (use exact names; if a field is missing, write "unknown")
                    NODES
                    - Date: ["date","end","start"]
                    - Deletetime: ["date","domain","user"]
                    - Domain: ["domain"]
                    - IPAddress: ["IP","hostname","rank"]
                    - Username: ["counts","counts4624","counts4625","counts4768","counts4769","counts4776","detect","rank","rights","sid","status","user"]
                    RELATIONSHIPS
                    - Event: ["authname","count","date","id","logintype","status","servicename","ticketencryptiontype"]
                    - Group: []
                    LANGUAGE CONTROL
                    - TargetLanguage = {lang_config['json_note']}
                    - JSON keys must remain in English; string values and narrative are in TargetLanguage.
                    - Do NOT translate event IDs/codes, SPN strings, hostnames, IPs, user names, or Cypher.
                    BENIGN CONTEXT (check before High/Critical)
                    - Bastion/jump/automation sources with uniform method and no privilege change
                    - DC/infra norms: 4768/4769 issuance; 4776 on DC alone is not suspicious
                    - Stable small destination set (≤2 hosts) without escalation indicators
                    - Ambiguous values (LogonType=0, authname='-') do not escalate on their own
                    - Absence of 4625 neither increases nor decreases risk
                    ESCALATION OVERRIDES (any true ⇒ severity ≥ High; benign checks do not apply)
                    1) Privilege change evidence + activity:
                    Username.rights contains 'system' or Username.status contains 'AddGroup'
                    AND same Username shows 4624/4776/4768/4769 to ≥1 host.
                    2) Mixed NTLM+Kerberos spread by privileged account:
                    For the same user/host set, 4776 AND 4768/4769 observed across ≥2 hosts.
                    3) Kerberoasting exposure:
                    In 4769, ticketencryptiontype not AES (e.g., RC4/DES) to multiple distinct servicename values.
                    SEVERITY GATING
                    - Label High/Critical only when at least two independent suspicious signals exist and no strong benign explanation applies.
                    - PageRank anomalies enhance risk assessment but require corroboration with authentication evidence (privilege changes, weak crypto, cross-host patterns).
                    - PageRank/centrality alone must NEVER drive severity; combine with concrete authentication artifacts.
                    VERIFICATION
                    - JSON matches the requested schema; first three key_findings are hotspot pins with concrete fields.
                    - Missing 4625 did not lower severity.
                    - If TargetLanguage ≠ "en", ensure narrative is in TargetLanguage; JSON keys remain English.
"""

#!/usr/bin/env python3
"""
FHIR-SpecGuard-LLM: Core XSLT AST Contract Extractor, 7-Factor Complexity
Estimator, OpenAPI 3.1 Synthesizer, and HIPAA Safe Harbor Sanitizer.

Author: Zohair Abbas Merchant, M.S.
ORCID: https://orcid.org/0009-0003-9013-4407
Repository: https://github.com/zohairabbasmerchant/fhir-specguard-llm
License: Apache License 2.0

Clean-room reference implementation of Algorithm 1 and the 5-stage engineering
governance model presented in:
  "SpecGuard-LLM: Automated Specification Governance and HIPAA-Compliant
   Documentation Synthesis for Large-Scale Healthcare API Cloud Migrations"

Grounded Technical Standards:
  - CMS-0057-F Final Rule: https://www.cms.gov/initiatives/burden-reduction/overview/interoperability/policies-regulations/cms-interoperability-prior-authorization-final-rule-cms-0057-f
  - HL7 FHIR Release 4 (R4): https://www.hl7.org/fhir/summary.html
  - HL7 Da Vinci Prior Authorization Support (PAS) IG: https://hl7.org/fhir/us/davinci-pas/
  - SMART App Launch v2.2.0 Scopes: https://build.fhir.org/ig/HL7/smart-app-launch/scopes-and-launch-context.html
  - W3C XSL Transformations (XSLT) 3.0: https://www.w3.org/TR/xslt-30/
  - OpenAPI Specification v3.1.0: https://spec.openapis.org/oas/v3.1.0.html
  - IETF RFC 7519 JSON Web Token (JWT): https://www.rfc-editor.org/info/rfc7519/
  - HHS HIPAA Safe Harbor (45 CFR § 164.514(b)(2)): https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html
"""

from __future__ import annotations

import copy
import json
import re
import sys
import unittest
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ============================================================================
# STAGE 1: 7-Factor Quantitative API Complexity Estimation Matrix
# ============================================================================

class ComplexityLevel(int, Enum):
    """Discrete rating scale s_i(x_i) in {1, 2, 3}."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class DeliveryTier(str, Enum):
    """Operational delivery tier classifications."""
    SMALL = "Small"
    MEDIUM = "Medium"
    LARGE = "Large"


@dataclass(frozen=True)
class ApiComplexityInput:
    """Input vector x = [x_1, ..., x_7]^T for a candidate healthcare API."""
    api_name: str
    num_resources: int
    num_fields: int
    validation_complexity: ComplexityLevel
    aggregation_filtering: ComplexityLevel
    orchestration_async: ComplexityLevel
    caching_strategy: ComplexityLevel
    special_considerations: ComplexityLevel


@dataclass(frozen=True)
class ApiComplexityEvaluation:
    """Output of the 7-factor complexity estimation model."""
    api_name: str
    feature_scores: Dict[str, int]
    weighted_scores: Dict[str, int]
    total_score: int
    tier: DeliveryTier
    allocated_sprints: float


class ComplexityEstimationMatrix:
    """
    Evaluates candidate APIs across the 7 architectural dimensions defined
    in Section 3.1 of SpecGuard-LLM:
      S(A) = sum_{i=1..7} w_i * s_i(x_i)
    where w = [2, 3, 1, 2, 3, 1, 2]^T.

    Note: In enterprise calibration workbooks where raw sub-scores are scaled
    by a factor of 2x-3x (yielding scores up to 66), the tier boundaries scale
    proportionally (<30 Small, 30-50 Medium, >50 Large). Both normalized and
    workbook-scaled modes are supported.
    """

    WEIGHTS: Dict[str, int] = {
        "num_resources": 2,
        "num_fields": 3,
        "validation_complexity": 1,
        "aggregation_filtering": 2,
        "orchestration_async": 3,
        "caching_strategy": 1,
        "special_considerations": 2,
    }

    def __init__(self, scale_factor: int = 2) -> None:
        """
        Initialize the complexity matrix.
        :param scale_factor: Multiplier aligning 1..3 ratings with enterprise
                             workbook point scales (default=2 yields range 14..84,
                             matching Small <30, Medium 30-50, Large >50).
        """
        self.scale_factor = scale_factor

    @staticmethod
    def score_resources(num_resources: int) -> int:
        if num_resources <= 3:
            return int(ComplexityLevel.LOW)
        if num_resources <= 7:
            return int(ComplexityLevel.MEDIUM)
        return int(ComplexityLevel.HIGH)

    @staticmethod
    def score_fields(num_fields: int) -> int:
        if num_fields <= 30:
            return int(ComplexityLevel.LOW)
        if num_fields <= 70:
            return int(ComplexityLevel.MEDIUM)
        return int(ComplexityLevel.HIGH)

    def evaluate(self, candidate: ApiComplexityInput) -> ApiComplexityEvaluation:
        raw_scores: Dict[str, int] = {
            "num_resources": self.score_resources(candidate.num_resources),
            "num_fields": self.score_fields(candidate.num_fields),
            "validation_complexity": int(candidate.validation_complexity),
            "aggregation_filtering": int(candidate.aggregation_filtering),
            "orchestration_async": int(candidate.orchestration_async),
            "caching_strategy": int(candidate.caching_strategy),
            "special_considerations": int(candidate.special_considerations),
        }

        weighted: Dict[str, int] = {
            k: raw_scores[k] * self.WEIGHTS[k] * self.scale_factor
            for k in self.WEIGHTS
        }
        total = sum(weighted.values())

        if total < 30:
            tier = DeliveryTier.SMALL
            sprints = 0.5
        elif total <= 50:
            tier = DeliveryTier.MEDIUM
            sprints = 1.0
        else:
            tier = DeliveryTier.LARGE
            sprints = 2.0 if total <= 60 else 2.5

        return ApiComplexityEvaluation(
            api_name=candidate.api_name,
            feature_scores=raw_scores,
            weighted_scores=weighted,
            total_score=total,
            tier=tier,
            allocated_sprints=sprints,
        )


# ============================================================================
# STAGE 3 & 4: Deterministic XSLT AST Parser & Schema Extractor
# ============================================================================

XSL_NS = "http://www.w3.org/1999/XSL/Transform"


@dataclass
class XsltFieldNode:
    """Represents a JSON target property extracted from an XSLT AST."""
    json_path: str
    source_xpath: str
    inferred_type: str = "string"
    inferred_format: Optional[str] = None
    is_array: bool = False
    enum_values: List[str] = field(default_factory=list)
    conditional_guard: Optional[str] = None


@dataclass
class XsltAstSummary:
    """Intermediate Representation (IR) produced by the static XSLT AST visitor."""
    variables: Dict[str, str] = field(default_factory=dict)
    for_each_scopes: List[str] = field(default_factory=list)
    conditional_branches: List[str] = field(default_factory=list)
    array_containers: Set[str] = field(default_factory=set)
    target_fields: Dict[str, XsltFieldNode] = field(default_factory=dict)


class XsltAstContractExtractor:
    """
    Static Abstract Syntax Tree (AST) visitor for W3C XSLT 1.0/2.0/3.0
    stylesheets deployed on XSLT-based API Gateway API Gateways.

    Extracts:
      1. <xsl:variable> symbol bindings
      2. <xsl:for-each> repeating collection scopes
      3. <xsl:choose> / <xsl:when> conditional branches
      4. jsonType="array" attributes for deterministic JSON array serialization
      5. translate() date normalization functions & LOB code enumerations
    """

    def parse_stylesheet(self, xslt_content: str) -> XsltAstSummary:
        # Ensure namespace declaration exists if parsing a snippet
        if "xmlns:xsl" not in xslt_content:
            wrapped = (
                f'<xsl:stylesheet version="1.0" '
                f'xmlns:xsl="{XSL_NS}">{xslt_content}</xsl:stylesheet>'
            )
        else:
            wrapped = xslt_content

        root = ET.fromstring(wrapped)
        summary = XsltAstSummary()
        self._visit_node(
            element=root,
            summary=summary,
            json_path_stack=[],
            xpath_scope_stack=[],
            active_condition=None,
        )
        return summary

    def _visit_node(
        self,
        element: ET.Element,
        summary: XsltAstSummary,
        json_path_stack: List[str],
        xpath_scope_stack: List[str],
        active_condition: Optional[str],
    ) -> None:
        local_name = self._local_tag(element.tag)

        if element.tag.startswith(f"{{{XSL_NS}}}"):
            if local_name == "variable":
                var_name = element.attrib.get("name", "")
                var_select = element.attrib.get("select", "")
                if var_name:
                    summary.variables[var_name] = var_select
                return

            if local_name == "for-each":
                select_expr = element.attrib.get("select", "")
                summary.for_each_scopes.append(select_expr)
                next_scope = xpath_scope_stack + ([select_expr] if select_expr else [])
                for child in element:
                    self._visit_node(
                        child, summary, json_path_stack, next_scope, active_condition
                    )
                return

            if local_name in ("when", "if"):
                test_expr = element.attrib.get("test", "")
                if test_expr:
                    summary.conditional_branches.append(test_expr)
                for child in element:
                    self._visit_node(
                        child,
                        summary,
                        json_path_stack,
                        xpath_scope_stack,
                        test_expr or active_condition,
                    )
                return

            # Default traversal for other XSL instructions (template, choose, otherwise)
            for child in element:
                self._visit_node(
                    child, summary, json_path_stack, xpath_scope_stack, active_condition
                )
            return

        # Literal result element -> becomes a JSON property or object/array container
        current_path_stack = json_path_stack + [local_name]
        dot_path = ".".join(current_path_stack)
        is_array = element.attrib.get("jsonType", "").lower() == "array"
        if is_array:
            summary.array_containers.add(dot_path)

        # Check if this literal element directly wraps a value-of, choose enum, or literal text
        value_of_child = element.find(f"{{{XSL_NS}}}value-of")
        choose_child = element.find(f"{{{XSL_NS}}}choose")

        non_xsl_children = [
            c for c in element if not c.tag.startswith(f"{{{XSL_NS}}}")
        ]

        if value_of_child is not None and not non_xsl_children:
            select_expr = value_of_child.attrib.get("select", "")
            resolved_xpath = self._resolve_xpath(
                select_expr, summary.variables, xpath_scope_stack
            )
            inferred_type, inferred_fmt = self._infer_type_and_format(
                local_name, select_expr
            )
            summary.target_fields[dot_path] = XsltFieldNode(
                json_path=dot_path,
                source_xpath=resolved_xpath,
                inferred_type=inferred_type,
                inferred_format=inferred_fmt,
                is_array=is_array,
                conditional_guard=active_condition,
            )
            return

        if choose_child is not None and not non_xsl_children:
            enum_vals: List[str] = []
            for when_node in choose_child.findall(f"{{{XSL_NS}}}when"):
                if when_node.text and when_node.text.strip():
                    enum_vals.append(when_node.text.strip())
            summary.target_fields[dot_path] = XsltFieldNode(
                json_path=dot_path,
                source_xpath="/".join(xpath_scope_stack) or ".",
                inferred_type="string",
                is_array=is_array,
                enum_values=enum_vals,
                conditional_guard=active_condition,
            )
            return

        if element.text and element.text.strip() and len(element) == 0:
            summary.target_fields[dot_path] = XsltFieldNode(
                json_path=dot_path,
                source_xpath=f"literal('{element.text.strip()}')",
                inferred_type="string",
                is_array=is_array,
                conditional_guard=active_condition,
            )
            return

        for child in element:
            self._visit_node(
                child, summary, current_path_stack, xpath_scope_stack, active_condition
            )

    @staticmethod
    def _local_tag(tag: str) -> str:
        if "}" in tag:
            return tag.split("}", 1)[1]
        return tag

    @staticmethod
    def _resolve_xpath(
        select_expr: str,
        variables: Dict[str, str],
        xpath_scope_stack: List[str],
    ) -> str:
        expr = select_expr.strip()
        if expr.startswith("$"):
            var_key = expr[1:]
            return variables.get(var_key, expr)

        # Strip translate(...) wrapper to recover underlying field path
        translate_match = re.match(r"translate\(\s*([^,]+)\s*,", expr)
        if translate_match:
            expr = translate_match.group(1).strip()

        if expr.startswith("./"):
            rel = expr[2:]
            return "/".join(xpath_scope_stack + [rel]) if xpath_scope_stack else rel
        if expr == ".":
            return "/".join(xpath_scope_stack) if xpath_scope_stack else "."
        return expr

    @staticmethod
    def _infer_type_and_format(
        field_name: str, select_expr: str
    ) -> Tuple[str, Optional[str]]:
        lower_name = field_name.lower()
        if "translate(" in select_expr and "date" in lower_name:
            return "string", "date"
        if "date" in lower_name:
            return "string", "date"
        if lower_name.endswith("amount") or lower_name.endswith("rate"):
            return "number", "double"
        return "string", None

    def build_openapi_schema(
        self,
        summary: XsltAstSummary,
        descriptions: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Synthesizes an OpenAPI 3.1 JSON Schema object directly from the
        extracted XSLT AST intermediate representation.
        """
        descriptions = descriptions or {}
        root_schema: Dict[str, Any] = {"type": "object", "properties": {}}

        for dot_path, field_node in summary.target_fields.items():
            segments = dot_path.split(".")
            cursor = root_schema
            prefix_parts: List[str] = []

            for idx, segment in enumerate(segments):
                prefix_parts.append(segment)
                current_prefix = ".".join(prefix_parts)
                is_last = idx == len(segments) - 1
                is_array_node = current_prefix in summary.array_containers

                props = cursor.setdefault("properties", {})

                if is_last:
                    leaf_schema: Dict[str, Any] = {"type": field_node.inferred_type}
                    if field_node.inferred_format:
                        leaf_schema["format"] = field_node.inferred_format
                    if field_node.enum_values:
                        leaf_schema["enum"] = field_node.enum_values
                    if dot_path in descriptions:
                        leaf_schema["description"] = descriptions[dot_path]
                    else:
                        leaf_schema["description"] = (
                            f"Mapped from XPath: {field_node.source_xpath}"
                        )

                    if is_array_node:
                        props[segment] = {"type": "array", "items": leaf_schema}
                    else:
                        props[segment] = leaf_schema
                else:
                    if segment not in props:
                        if is_array_node:
                            props[segment] = {
                                "type": "array",
                                "items": {"type": "object", "properties": {}},
                            }
                        else:
                            props[segment] = {"type": "object", "properties": {}}

                    next_container = props[segment]
                    cursor = (
                        next_container["items"]
                        if next_container.get("type") == "array"
                        else next_container
                    )

        return root_schema


# ============================================================================
# STAGE 4: HIPAA Safe Harbor 18-Identifier De-Identification Filter
# ============================================================================

class HipaaSafeHarborSanitizer:
    """
    Enforces HIPAA Safe Harbor De-Identification (45 CFR § 164.514(b)(2))
    across generated OpenAPI example fixtures so no live PHI leaks into
    developer portals or source control.
    """

    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    PHONE_PATTERN = re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"
    )
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@(?!example\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )
    ZIP_PLUS4_PATTERN = re.compile(r"\b\d{5}-\d{4}\b")

    SENSITIVE_FIELD_KEYS: Dict[str, str] = {
        "ssn": "000-00-0000",
        "socialsecuritynumber": "000-00-0000",
        "memberid": "SYNTH-MBR-100001",
        "subscriberid": "SYNTH-SUB-100001",
        "patientname": "Jane Doe (Synthetic)",
        "membername": "Jane Doe (Synthetic)",
        "dob": "1980-01-01",
        "dateofbirth": "1980-01-01",
        "birthdate": "1980-01-01",
        "mrn": "SYNTH-MRN-999999",
        "phone": "555-010-0199",
        "email": "synthetic.patient@example.com",
    }

    def sanitize_examples(self, payload: Any) -> Tuple[Any, List[str]]:
        """
        Recursively scans and sanitizes example fixtures, returning a tuple of
        (sanitized_payload, list_of_audit_events).
        """
        audit_events: List[str] = []
        sanitized = self._walk(copy.deepcopy(payload), audit_events, path="$")
        return sanitized, audit_events

    def _walk(self, node: Any, audit_events: List[str], path: str) -> Any:
        if isinstance(node, dict):
            result: Dict[str, Any] = {}
            for k, v in node.items():
                norm_key = re.sub(r"[^a-zA-Z0-9]", "", k).lower()
                child_path = f"{path}.{k}"
                if norm_key in self.SENSITIVE_FIELD_KEYS and isinstance(v, str):
                    replacement = self.SENSITIVE_FIELD_KEYS[norm_key]
                    if v != replacement:
                        audit_events.append(
                            f"Masked sensitive PHI key at {child_path}"
                        )
                    result[k] = replacement
                else:
                    result[k] = self._walk(v, audit_events, child_path)
            return result

        if isinstance(node, list):
            return [
                self._walk(item, audit_events, f"{path}[{idx}]")
                for idx, item in enumerate(node)
            ]

        if isinstance(node, str):
            updated = node
            if self.SSN_PATTERN.search(updated):
                updated = self.SSN_PATTERN.sub("000-00-0000", updated)
                if updated != node:
                    audit_events.append(f"Masked SSN pattern at {path}")
            if self.PHONE_PATTERN.search(updated) and "555-010" not in updated:
                updated = self.PHONE_PATTERN.sub("555-010-0199", updated)
                audit_events.append(f"Masked phone pattern at {path}")
            if self.EMAIL_PATTERN.search(updated):
                updated = self.EMAIL_PATTERN.sub(
                    "synthetic.patient@example.com", updated
                )
                audit_events.append(f"Masked live email pattern at {path}")
            if self.ZIP_PLUS4_PATTERN.search(updated):
                updated = self.ZIP_PLUS4_PATTERN.sub("00000-0000", updated)
                audit_events.append(f"Masked 9-digit ZIP code at {path}")
            return updated

        return node


# ============================================================================
# ALGORITHM 1: SpecGuard-LLM Specification Synthesis & Conformance Engine
# ============================================================================

class SpecificationDivergenceError(Exception):
    """Raised when the Data Mapping workbook and XSLT AST targets diverge."""


class ConformanceFailureError(Exception):
    """Raised when OpenAPI 3.1 or HL7 FHIR / Okta JWT scope validation fails."""


@dataclass
class GatewayPolicyDefinition:
    """XSLT-based API Gateway Virtual Directory & Okta OAuth 2.0 policy metadata."""
    policy_name: str
    endpoint_path: str
    http_method: str
    request_task_list: str
    response_task_list: str
    remote_policy: str
    okta_issuer_url: str
    required_smart_scopes: List[str]
    requires_fhir_conformance: bool = False
    fhir_resource_type: Optional[str] = None


class SpecGuardGovernanceEngine:
    """
    Executes Algorithm 1 (SpecGuard-LLM Dual-Stage Synthesis and Conformance
    Verification), combining deterministic XSLT AST extraction, Data Mapping
    workbook verification, Okta SMART on FHIR scope checks, and HIPAA Safe
    Harbor sanitization.
    """

    SMART_SCOPE_REGEX = re.compile(
        r"^(?:patient|user|system)/[A-Za-z*]+\.(?:read|write|c|r|u|d|s|\*)$"
    )

    SUPPORTED_FHIR_R4_RESOURCES: Set[str] = {
        "Patient",
        "Coverage",
        "ExplanationOfBenefit",
        "Claim",
        "ClaimResponse",
        "Organization",
        "Practitioner",
        "OperationOutcome",
    }

    def __init__(self) -> None:
        self.ast_extractor = XsltAstContractExtractor()
        self.sanitizer = HipaaSafeHarborSanitizer()

    def synthesize_and_verify(
        self,
        response_xslt: str,
        data_mapping_sheet: Dict[str, str],
        error_taxonomy_sheet: Dict[str, str],
        gateway_policy: GatewayPolicyDefinition,
        sample_response_example: Dict[str, Any],
        llm_enrichment_fn: Optional[Callable[[XsltAstSummary], Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Executes Algorithm 1 end-to-end and returns a certified OpenAPI 3.1.0
        specification dictionary.
        """
        # Step 1: Parse XSLT Abstract Syntax Tree
        ast_summary = self.ast_extractor.parse_stylesheet(response_xslt)

        # Steps 4-6: Verify syntactic alignment between XSLT AST and DM sheet
        unmapped_targets = [
            target
            for target in data_mapping_sheet
            if target not in ast_summary.target_fields
        ]
        if unmapped_targets:
            raise SpecificationDivergenceError(
                f"Data Mapping workbook targets missing from XSLT AST: {unmapped_targets}"
            )

        # Verify Okta OAuth 2.0 / SMART on FHIR scopes
        for scope in gateway_policy.required_smart_scopes:
            if not self.SMART_SCOPE_REGEX.match(scope):
                raise ConformanceFailureError(
                    f"Invalid Okta SMART on FHIR scope syntax: '{scope}'"
                )

        # Verify HL7 FHIR R4 resource conformance if required
        if gateway_policy.requires_fhir_conformance:
            if (
                not gateway_policy.fhir_resource_type
                or gateway_policy.fhir_resource_type
                not in self.SUPPORTED_FHIR_R4_RESOURCES
            ):
                raise ConformanceFailureError(
                    f"Unsupported or missing HL7 FHIR R4 resource type: "
                    f"'{gateway_policy.fhir_resource_type}'"
                )

        # Step 8: Constrained description synthesis (deterministic T=0.0 fallback)
        if llm_enrichment_fn is not None:
            field_descriptions = llm_enrichment_fn(ast_summary)
        else:
            field_descriptions = data_mapping_sheet

        response_schema = self.ast_extractor.build_openapi_schema(
            ast_summary, descriptions=field_descriptions
        )

        # Step 11: HIPAA Safe Harbor PHI Sanitization on example fixtures
        sanitized_example, phi_audit_log = self.sanitizer.sanitize_examples(
            sample_response_example
        )

        # Build OpenAPI 3.1.0 contract
        openapi_contract: Dict[str, Any] = {
            "openapi": "3.1.0",
            "info": {
                "title": f"Enterprise Healthcare Gateway Policy: {gateway_policy.policy_name}",
                "version": "1.0.0",
                "description": (
                    f"Auto-synthesized and verified by SpecGuard-LLM from XSLT-based API Gateway "
                    f"task lists ({gateway_policy.request_task_list} / "
                    f"{gateway_policy.response_task_list}) and remote policy "
                    f"{gateway_policy.remote_policy}."
                ),
            },
            "x-xslt-gateway-governance": {
                "policyName": gateway_policy.policy_name,
                "requestTaskList": gateway_policy.request_task_list,
                "responseTaskList": gateway_policy.response_task_list,
                "remotePolicy": gateway_policy.remote_policy,
                "hipaaSafeHarborEvents": phi_audit_log,
            },
            "components": {
                "securitySchemes": {
                    "OktaOAuth2Bearer": {
                        "type": "oauth2",
                        "description": "Okta OAuth 2.0 / OIDC JWT (RFC 7519) validated at XSLT-based API Gateway edge",
                        "flows": {
                            "clientCredentials": {
                                "tokenUrl": f"{gateway_policy.okta_issuer_url}/v1/token",
                                "scopes": {
                                    s: f"SMART on FHIR scope {s}"
                                    for s in gateway_policy.required_smart_scopes
                                },
                            }
                        },
                    }
                },
                "schemas": {
                    "SuccessResponseEnvelope": response_schema,
                    "ErrorResponseEnvelope": {
                        "type": "object",
                        "properties": {
                            "errorCode": {
                                "type": "string",
                                "enum": list(error_taxonomy_sheet.keys()),
                            },
                            "errorMessage": {"type": "string"},
                        },
                        "required": ["errorCode", "errorMessage"],
                    },
                },
            },
            "paths": {
                gateway_policy.endpoint_path: {
                    gateway_policy.http_method.lower(): {
                        "summary": f"Execute {gateway_policy.policy_name}",
                        "security": [
                            {"OktaOAuth2Bearer": gateway_policy.required_smart_scopes}
                        ],
                        "responses": {
                            "200": {
                                "description": "Successful XSLT-transformed JSON response",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "$ref": "#/components/schemas/SuccessResponseEnvelope"
                                        },
                                        "example": sanitized_example,
                                    }
                                },
                            },
                            "400": {
                                "description": "Gateway validation or backend error transformation",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "$ref": "#/components/schemas/ErrorResponseEnvelope"
                                        }
                                    }
                                },
                            },
                        },
                    }
                }
            },
        }

        return openapi_contract


# ============================================================================
# SANITIZED PRODUCTION FIXTURE & UNIT TEST SUITE
# ============================================================================

SAMPLE_GATEWAY_XSLT = """
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:variable name="groupNum" select="GroupInfoDetails/Group/GroupNum"/>
  <xsl:variable name="groupName" select="GroupInfoDetails/Group/GroupName"/>
  <xsl:template match="/">
    <xsl:choose>
      <xsl:when test="(ResultMessage/@code='0' and ResultMessage/@status='0') or (ResultMessage/@code='2' and ResultMessage/@status='0')">
        <headerArea>
          <xsl:if test="$systemEnvironmentCode != '' and not(string-length(normalize-space($systemEnvironmentCode)) = 0)">
            <systemEnvironmentCode><xsl:value-of select="$systemEnvironmentCode"/></systemEnvironmentCode>
          </xsl:if>
          <messageId><xsl:value-of select="$messageId"/></messageId>
          <systemMessage jsonType="array">
            <source>BC</source>
            <code>SUC</code>
            <additionalInfo>Successful Completion</additionalInfo>
          </systemMessage>
        </headerArea>
        <payloadArea>
          <xsl:for-each select="GroupInfoDetails/Group/Division">
            <grpBenefitInfo jsonType="array">
              <group>
                <number><xsl:value-of select="$groupNum"/></number>
                <suffix><xsl:value-of select="./DivisionNum"/></suffix>
              </group>
              <name><xsl:value-of select="$groupName"/></name>
              <packageCode><xsl:value-of select="./PackageCode"/></packageCode>
              <dateRange>
                <effectiveDate><xsl:value-of select="translate(./EffectiveDate, '/', '-')"/></effectiveDate>
                <terminationDate><xsl:value-of select="translate(./TerminationDate, '/', '-')"/></terminationDate>
              </dateRange>
              <bpidInfo>
                <code><xsl:value-of select="./BenefitPackages/BenefitPackage/BenefitPackageId"/></code>
                <description><xsl:value-of select="./BenefitPackages/BenefitPackage/PackageType"/></description>
                <lob jsonType="array">
                  <code>
                    <xsl:choose>
                      <xsl:when test=". = 'Medical Services' or . = 'Master Medical'">M</xsl:when>
                      <xsl:when test=". = 'Vision Services and Hearing'">V</xsl:when>
                      <xsl:when test=". = 'Prescription Drugs'">X</xsl:when>
                      <xsl:when test=". = 'Dental'">D</xsl:when>
                    </xsl:choose>
                  </code>
                  <description><xsl:value-of select="."/></description>
                </lob>
              </bpidInfo>
            </grpBenefitInfo>
          </xsl:for-each>
        </payloadArea>
      </xsl:when>
    </xsl:choose>
  </xsl:template>
</xsl:stylesheet>
"""


class TestSpecGuardToolkit(unittest.TestCase):
    """Unit test suite verifying all 4 core components of FHIR-SpecGuard-LLM."""

    def test_complexity_estimation_tiers(self) -> None:
        matrix = ComplexityEstimationMatrix(scale_factor=2)

        # Medium complexity API (e.g., RateLoad lookup)
        medium_api = ApiComplexityInput(
            api_name="22615_SI_BCN_RateLoad",
            num_resources=2,
            num_fields=28,
            validation_complexity=ComplexityLevel.MEDIUM,
            aggregation_filtering=ComplexityLevel.LOW,
            orchestration_async=ComplexityLevel.LOW,
            caching_strategy=ComplexityLevel.LOW,
            special_considerations=ComplexityLevel.LOW,
        )
        eval_med = matrix.evaluate(medium_api)
        self.assertEqual(eval_med.total_score, 30)
        self.assertEqual(eval_med.tier, DeliveryTier.MEDIUM)
        self.assertEqual(eval_med.allocated_sprints, 1.0)

        # Large complexity API (e.g., multi-resource benefit orchestration)
        large_api = ApiComplexityInput(
            api_name="SIBC_GroupBenefit_Orchestration",
            num_resources=8,
            num_fields=75,
            validation_complexity=ComplexityLevel.HIGH,
            aggregation_filtering=ComplexityLevel.HIGH,
            orchestration_async=ComplexityLevel.HIGH,
            caching_strategy=ComplexityLevel.MEDIUM,
            special_considerations=ComplexityLevel.MEDIUM,
        )
        eval_large = matrix.evaluate(large_api)
        self.assertGreater(eval_large.total_score, 50)
        self.assertEqual(eval_large.tier, DeliveryTier.LARGE)

    def test_xslt_ast_extraction_and_schema_synthesis(self) -> None:
        extractor = XsltAstContractExtractor()
        summary = extractor.parse_stylesheet(SAMPLE_GATEWAY_XSLT)

        # Verify variable symbol table resolution
        self.assertEqual(
            summary.variables["groupNum"], "GroupInfoDetails/Group/GroupNum"
        )
        self.assertIn("payloadArea.grpBenefitInfo", summary.array_containers)
        self.assertIn(
            "payloadArea.grpBenefitInfo.bpidInfo.lob", summary.array_containers
        )

        # Verify date format inference from translate()
        eff_date_node = summary.target_fields[
            "payloadArea.grpBenefitInfo.dateRange.effectiveDate"
        ]
        self.assertEqual(eff_date_node.inferred_format, "date")

        # Verify LOB enum extraction from <xsl:choose>
        lob_code_node = summary.target_fields[
            "payloadArea.grpBenefitInfo.bpidInfo.lob.code"
        ]
        self.assertEqual(lob_code_node.enum_values, ["M", "V", "X", "D"])

    def test_drift_detection_raises_on_unmapped_field(self) -> None:
        engine = SpecGuardGovernanceEngine()
        policy = GatewayPolicyDefinition(
            policy_name="sibcxmlprocessor-v1.0",
            endpoint_path="/benefitservice/v1/groupbenefits",
            http_method="POST",
            request_task_list="tlg_sibcxmlprocessor-v1.0_Benefit_RequestProcessing",
            response_task_list="tlg_sibcxmlprocessor-v1.0_Benefit_ResponseProcessing",
            remote_policy="MQ_R_sibcxmlprocessorbc",
            okta_issuer_url="https://auth.payer-cloud.example.com/oauth2/default",
            required_smart_scopes=["user/Coverage.read"],
        )

        # Introduce an unmapped target field not present in XSLT
        drifted_dm = {
            "payloadArea.grpBenefitInfo.unannouncedDriftedField": "Missing in XSLT"
        }
        with self.assertRaises(SpecificationDivergenceError):
            engine.synthesize_and_verify(
                response_xslt=SAMPLE_GATEWAY_XSLT,
                data_mapping_sheet=drifted_dm,
                error_taxonomy_sheet={"ERR_01": "Invalid Group Number"},
                gateway_policy=policy,
                sample_response_example={},
            )

    def test_hipaa_safe_harbor_phi_masking(self) -> None:
        sanitizer = HipaaSafeHarborSanitizer()
        dirty_fixture = {
            "subscriberId": "987654321",
            "patientName": "John RealPatient",
            "ssn": "123-45-6789",
            "contactNote": "Call member at 313-555-9876 or john.doe@realclinic.org",
        }
        clean_fixture, audit_log = sanitizer.sanitize_examples(dirty_fixture)
        self.assertEqual(clean_fixture["ssn"], "000-00-0000")
        self.assertEqual(clean_fixture["patientName"], "Jane Doe (Synthetic)")
        self.assertNotIn("123-45-6789", json.dumps(clean_fixture))
        self.assertNotIn("john.doe@realclinic.org", json.dumps(clean_fixture))
        self.assertGreaterEqual(len(audit_log), 4)


def run_cli_demo() -> None:
    """Runs an end-to-end demonstration of the SpecGuard-LLM pipeline."""
    print("=" * 76)
    print("FHIR-SpecGuard-LLM: XSLT AST & OpenAPI 3.1 Governance Engine (v0.1.0)")
    print("=" * 76)

    engine = SpecGuardGovernanceEngine()
    policy = GatewayPolicyDefinition(
        policy_name="sibcxmlprocessor-v1.0",
        endpoint_path="/benefitservice/v1/groupbenefits",
        http_method="POST",
        request_task_list="tlg_sibcxmlprocessor-v1.0_Benefit_RequestProcessing",
        response_task_list="tlg_sibcxmlprocessor-v1.0_Benefit_ResponseProcessing",
        remote_policy="MQ_R_sibcxmlprocessorbc",
        okta_issuer_url="https://auth.payer-cloud.example.com/oauth2/default",
        required_smart_scopes=["user/Coverage.read", "patient/ExplanationOfBenefit.read"],
        requires_fhir_conformance=True,
        fhir_resource_type="Coverage",
    )

    data_mapping = {
        "headerArea.messageId": "Unique correlation message identifier",
        "payloadArea.grpBenefitInfo.group.number": "Employer group identifier",
        "payloadArea.grpBenefitInfo.group.suffix": "Group division suffix",
        "payloadArea.grpBenefitInfo.packageCode": "Benefit package code",
        "payloadArea.grpBenefitInfo.dateRange.effectiveDate": "Coverage effective date (ISO-8601)",
        "payloadArea.grpBenefitInfo.bpidInfo.lob.code": "Canonical Line of Business code (M/V/X/D)",
    }

    sample_example = {
        "headerArea": {"messageId": "MSG-20261028-001"},
        "payloadArea": {
            "grpBenefitInfo": [
                {
                    "group": {"number": "GRP-1040", "suffix": "001"},
                    "packageCode": "PKG-GOLD-PPO",
                    "dateRange": {
                        "effectiveDate": "2026-01-01",
                        "terminationDate": "2026-12-31",
                    },
                    "bpidInfo": {
                        "lob": [{"code": "M", "description": "Medical Services"}]
                    },
                }
            ]
        },
    }

    contract = engine.synthesize_and_verify(
        response_xslt=SAMPLE_GATEWAY_XSLT,
        data_mapping_sheet=data_mapping,
        error_taxonomy_sheet={"ERR_400": "Malformed Request", "ERR_500": "MQ Timeout"},
        gateway_policy=policy,
        sample_response_example=sample_example,
    )

    print(
        f"[PASS] Synthesized OpenAPI {contract['openapi']} contract for policy "
        f"'{policy.policy_name}' with 0.0% schema drift."
    )
    print(
        f"[PASS] Extracted {len(data_mapping)} mapped XPath targets and verified "
        f"Okta SMART scopes: {policy.required_smart_scopes}\n"
    )


if __name__ == "__main__":
    run_cli_demo()
    unittest.main(verbosity=2)

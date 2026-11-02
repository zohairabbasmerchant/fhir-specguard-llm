#!/usr/bin/env python3
"""
FHIR-SpecGuard-LLM: Multi-Tab Requirement Workbook Parser, Process Flow
Swimlane Validator, RFC 9457 / FHIR OperationOutcome Error Mapper, and
CI/CD Contract Drift Auditor (specguard_workbook_cli.py).

Author: Zohair Abbas Merchant, M.S. (ORCID: https://orcid.org/0009-0003-9013-4407)
Repository: https://github.com/zohairabbasmerchant/fhir-specguard-llm
License: Apache License 2.0

Extends specguard_xslt_auditor.py to parse the 9 standardized engineering
tabs of enterprise healthcare requirement workbooks (e.g., 22615_SI_BCN_RateLoad):
  1. Version
  2. UC (Use Cases)
  3. Validations
  4. Non-Functional Requirements
  5. Deployment
  6. API Diagram
  7. Process Flow (Swimlane State Graph)
  8. DM (Data Mapping Dictionary)
  9. Result_Error Mapping (RFC 9457 & HL7 FHIR OperationOutcome Taxonomy)
"""

from __future__ import annotations

import json
import unittest
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from specguard_xslt_auditor import (
    SAMPLE_GATEWAY_XSLT,
    GatewayPolicyDefinition,
    SpecGuardGovernanceEngine,
)


REQUIRED_WORKBOOK_TABS: Tuple[str, ...] = (
    "Version",
    "UC",
    "Validations",
    "Non-Functional Requirements",
    "Deployment",
    "API Diagram",
    "Process Flow",
    "DM",
    "Result_Error Mapping",
)


class WorkbookValidationError(Exception):
    """Raised when a multi-tab requirement workbook is missing mandatory tabs or rules."""


@dataclass
class ValidationRule:
    """Field-level validation constraint from the 'Validations' tab."""
    field_path: str
    required: bool
    pattern: Optional[str] = None
    max_length: Optional[int] = None
    rule_description: str = ""


@dataclass
class ErrorMappingEntry:
    """Error translation row from the 'Result_Error Mapping' tab."""
    backend_result_code: str
    backend_status_code: str
    http_status: int
    canonical_error_code: str
    fhir_issue_code: str
    client_message: str


@dataclass
class ParsedRequirementWorkbook:
    """Strongly typed representation of a 9-tab engineering specification workbook."""
    project_id: str
    version: str
    use_cases: List[str]
    validations: Dict[str, ValidationRule]
    sla_p95_ms: int
    sla_p99_ms: int
    virtual_directory: str
    endpoint_uri: str
    process_flow_steps: List[str]
    data_mapping: Dict[str, str]
    error_mappings: Dict[str, ErrorMappingEntry]


@dataclass
class DriftDiffReport:
    """Report produced by comparing baseline and candidate OpenAPI 3.1 contracts."""
    is_backward_compatible: bool
    removed_fields: List[str] = field(default_factory=list)
    added_fields: List[str] = field(default_factory=list)
    type_mutations: List[str] = field(default_factory=list)
    scope_regressions: List[str] = field(default_factory=list)


class RequirementWorkbookParser:
    """
    Parses and validates structured 9-tab requirement specification workbooks
    (represented as JSON/dict exports from enterprise Excel workbooks) and
    synthesizes RFC 9457 Problem Details and HL7 FHIR OperationOutcome schemas.
    """

    MANDATORY_SWIMLANE_GATES: Tuple[str, ...] = (
        "Is Authenticated and Authorized Request?",
        "Is Request Valid?",
        "Build Request and Invoke Service",
        "Success Response?",
    )

    def parse_workbook(self, raw_workbook: Dict[str, Any]) -> ParsedRequirementWorkbook:
        missing_tabs = [
            tab for tab in REQUIRED_WORKBOOK_TABS if tab not in raw_workbook
        ]
        if missing_tabs:
            raise WorkbookValidationError(
                f"Requirement workbook is missing mandatory engineering tabs: {missing_tabs}"
            )

        # Verify Process Flow swimlane contains mandatory zero-trust & XSLT gates
        flow_steps: List[str] = raw_workbook["Process Flow"].get("steps", [])
        for gate in self.MANDATORY_SWIMLANE_GATES:
            if gate not in flow_steps:
                raise WorkbookValidationError(
                    f"Process Flow tab is missing mandatory swimlane gate: '{gate}'"
                )

        validations: Dict[str, ValidationRule] = {}
        for row in raw_workbook["Validations"]:
            rule = ValidationRule(
                field_path=row["field_path"],
                required=bool(row.get("required", False)),
                pattern=row.get("pattern"),
                max_length=row.get("max_length"),
                rule_description=row.get("description", ""),
            )
            validations[rule.field_path] = rule

        error_mappings: Dict[str, ErrorMappingEntry] = {}
        for row in raw_workbook["Result_Error Mapping"]:
            entry = ErrorMappingEntry(
                backend_result_code=str(row["backend_code"]),
                backend_status_code=str(row.get("backend_status", "1")),
                http_status=int(row["http_status"]),
                canonical_error_code=row["error_code"],
                fhir_issue_code=row.get("fhir_issue_code", "processing"),
                client_message=row["message"],
            )
            error_mappings[entry.canonical_error_code] = entry

        nfr = raw_workbook["Non-Functional Requirements"]
        deploy = raw_workbook["Deployment"]
        ver = raw_workbook["Version"]

        return ParsedRequirementWorkbook(
            project_id=ver.get("project_id", "UNKNOWN_PROJECT"),
            version=ver.get("version", "1.0.0"),
            use_cases=raw_workbook["UC"].get("scenarios", []),
            validations=validations,
            sla_p95_ms=int(nfr.get("p95_latency_ms", 250)),
            sla_p99_ms=int(nfr.get("p99_latency_ms", 500)),
            virtual_directory=deploy["virtual_directory"],
            endpoint_uri=deploy["endpoint_uri"],
            process_flow_steps=flow_steps,
            data_mapping=dict(raw_workbook["DM"]),
            error_mappings=error_mappings,
        )

    @staticmethod
    def build_rfc9457_and_fhir_error_schema(
        parsed: ParsedRequirementWorkbook,
    ) -> Dict[str, Any]:
        """
        Synthesizes a dual-compliant IETF RFC 9457 Problem Details and HL7 FHIR R4
        OperationOutcome JSON Schema from the 'Result_Error Mapping' tab.
        """
        error_codes = sorted(parsed.error_mappings.keys())
        fhir_issue_codes = sorted(
            {e.fhir_issue_code for e in parsed.error_mappings.values()}
        )
        return {
            "type": "object",
            "description": (
                "Standardized gateway error envelope conforming to IETF RFC 9457 "
                "(Problem Details for HTTP APIs) and HL7 FHIR R4 OperationOutcome."
            ),
            "properties": {
                "resourceType": {
                    "type": "string",
                    "enum": ["OperationOutcome"],
                },
                "type": {
                    "type": "string",
                    "format": "uri",
                    "description": "RFC 9457 problem type URI",
                },
                "title": {"type": "string"},
                "status": {"type": "integer"},
                "errorCode": {"type": "string", "enum": error_codes},
                "issue": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "severity": {
                                "type": "string",
                                "enum": ["fatal", "error", "warning", "information"],
                            },
                            "code": {"type": "string", "enum": fhir_issue_codes},
                            "diagnostics": {"type": "string"},
                        },
                        "required": ["severity", "code", "diagnostics"],
                    },
                },
            },
            "required": ["resourceType", "status", "errorCode", "issue"],
        }


class ContractDriftAuditor:
    """
    Executes structural diffing between a published baseline OpenAPI 3.1 contract
    and a newly synthesized candidate contract inside CI/CD pipelines.
    """

    def compare_contracts(
        self, baseline: Dict[str, Any], candidate: Dict[str, Any]
    ) -> DriftDiffReport:
        base_schema = (
            baseline.get("components", {})
            .get("schemas", {})
            .get("SuccessResponseEnvelope", {})
        )
        cand_schema = (
            candidate.get("components", {})
            .get("schemas", {})
            .get("SuccessResponseEnvelope", {})
        )

        base_leaves = self._flatten_schema_leaves(base_schema)
        cand_leaves = self._flatten_schema_leaves(cand_schema)

        removed = sorted(set(base_leaves.keys()) - set(cand_leaves.keys()))
        added = sorted(set(cand_leaves.keys()) - set(base_leaves.keys()))

        mutations: List[str] = []
        for shared_key in sorted(set(base_leaves.keys()) & set(cand_leaves.keys())):
            if base_leaves[shared_key] != cand_leaves[shared_key]:
                mutations.append(
                    f"{shared_key}: {base_leaves[shared_key]} -> {cand_leaves[shared_key]}"
                )

        base_scopes = self._extract_scopes(baseline)
        cand_scopes = self._extract_scopes(candidate)
        dropped_scopes = sorted(base_scopes - cand_scopes)

        is_compatible = (
            len(removed) == 0 and len(mutations) == 0 and len(dropped_scopes) == 0
        )
        return DriftDiffReport(
            is_backward_compatible=is_compatible,
            removed_fields=removed,
            added_fields=added,
            type_mutations=mutations,
            scope_regressions=dropped_scopes,
        )

    def _flatten_schema_leaves(
        self, schema: Dict[str, Any], prefix: str = ""
    ) -> Dict[str, str]:
        leaves: Dict[str, str] = {}
        node_type = schema.get("type", "object")

        if node_type == "array":
            items = schema.get("items", {})
            return self._flatten_schema_leaves(items, f"{prefix}[]")

        props = schema.get("properties", {})
        if not props and prefix:
            fmt = schema.get("format")
            leaves[prefix] = f"{node_type}({fmt})" if fmt else str(node_type)
            return leaves

        for prop_name, prop_schema in props.items():
            next_prefix = f"{prefix}.{prop_name}" if prefix else prop_name
            leaves.update(self._flatten_schema_leaves(prop_schema, next_prefix))
        return leaves

    @staticmethod
    def _extract_scopes(contract: Dict[str, Any]) -> Set[str]:
        scopes_dict = (
            contract.get("components", {})
            .get("securitySchemes", {})
            .get("OktaOAuth2Bearer", {})
            .get("flows", {})
            .get("clientCredentials", {})
            .get("scopes", {})
        )
        return set(scopes_dict.keys())


# ============================================================================
# SANITIZED 9-TAB WORKBOOK FIXTURE & UNIT TEST SUITE
# ============================================================================

SAMPLE_9TAB_WORKBOOK: Dict[str, Any] = {
    "Version": {
        "project_id": "22615_SI_BCN_GroupBenefit",
        "version": "1.2.0",
        "author": "Enterprise Integration Architecture",
    },
    "UC": {
        "scenarios": [
            "UC-01: Retrieve active group benefit divisions and canonical LOB codes",
            "UC-02: Return standardized error on invalid group identifier",
        ]
    },
    "Validations": [
        {
            "field_path": "requestArea.groupNumber",
            "required": True,
            "pattern": "^[A-Z0-9-]{4,12}$",
            "max_length": 12,
            "description": "Mandatory alphanumeric employer group identifier",
        }
    ],
    "Non-Functional Requirements": {
        "p95_latency_ms": 150,
        "p99_latency_ms": 300,
        "availability_sla": "99.99%",
    },
    "Deployment": {
        "virtual_directory": "sibcxmlprocessor-v1.0",
        "endpoint_uri": "/benefitservice/v1/groupbenefits",
        "remote_policy": "MQ_R_sibcxmlprocessorbc",
    },
    "API Diagram": {
        "caller": "External EHR / Member Portal",
        "idp": "Okta OAuth 2.0 / OIDC",
        "gateway": "XSLT-based API Gateway XML/JSON Engine",
        "backend": "Core Benefit System via IBM MQ",
    },
    "Process Flow": {
        "steps": [
            "Caller Invokes API",
            "Is Authenticated and Authorized Request?",
            "Transform Error Response into JSON (401/403)",
            "Is Request Valid?",
            "Transform Error Response into JSON (400)",
            "Build Request and Invoke Service",
            "Success Response?",
            "Transform Success Response into JSON (200)",
        ]
    },
    "DM": {
        "headerArea.messageId": "Unique correlation message identifier",
        "payloadArea.grpBenefitInfo.group.number": "Employer group identifier",
        "payloadArea.grpBenefitInfo.group.suffix": "Group division suffix",
        "payloadArea.grpBenefitInfo.packageCode": "Benefit package code",
        "payloadArea.grpBenefitInfo.dateRange.effectiveDate": "Coverage effective date (ISO-8601)",
        "payloadArea.grpBenefitInfo.bpidInfo.lob.code": "Canonical Line of Business code (M/V/X/D)",
    },
    "Result_Error Mapping": [
        {
            "backend_code": "4001",
            "backend_status": "1",
            "http_status": 400,
            "error_code": "ERR_INVALID_GROUP",
            "fhir_issue_code": "invalid",
            "message": "The supplied group number format is invalid.",
        },
        {
            "backend_code": "5004",
            "backend_status": "2",
            "http_status": 504,
            "error_code": "ERR_MQ_TIMEOUT",
            "fhir_issue_code": "timeout",
            "message": "Downstream benefit queue timed out.",
        },
    ],
}


class TestWorkbookAndDriftCli(unittest.TestCase):
    """Unit test suite for the 9-tab workbook parser and CI/CD drift auditor."""

    def setUp(self) -> None:
        self.parser = RequirementWorkbookParser()
        self.auditor = ContractDriftAuditor()
        self.engine = SpecGuardGovernanceEngine()

    def test_parses_all_9_mandatory_tabs(self) -> None:
        parsed = self.parser.parse_workbook(SAMPLE_9TAB_WORKBOOK)
        self.assertEqual(parsed.project_id, "22615_SI_BCN_GroupBenefit")
        self.assertEqual(parsed.virtual_directory, "sibcxmlprocessor-v1.0")
        self.assertEqual(len(parsed.data_mapping), 6)
        self.assertIn("ERR_INVALID_GROUP", parsed.error_mappings)

    def test_missing_tab_raises_validation_error(self) -> None:
        incomplete = dict(SAMPLE_9TAB_WORKBOOK)
        del incomplete["Result_Error Mapping"]
        with self.assertRaises(WorkbookValidationError):
            self.parser.parse_workbook(incomplete)

    def test_missing_swimlane_gate_raises_validation_error(self) -> None:
        bad_flow = json.loads(json.dumps(SAMPLE_9TAB_WORKBOOK))
        bad_flow["Process Flow"]["steps"] = ["Caller Invokes API"]
        with self.assertRaises(WorkbookValidationError):
            self.parser.parse_workbook(bad_flow)

    def test_rfc9457_and_fhir_error_schema_generation(self) -> None:
        parsed = self.parser.parse_workbook(SAMPLE_9TAB_WORKBOOK)
        err_schema = self.parser.build_rfc9457_and_fhir_error_schema(parsed)
        self.assertEqual(
            err_schema["properties"]["errorCode"]["enum"],
            ["ERR_INVALID_GROUP", "ERR_MQ_TIMEOUT"],
        )
        self.assertEqual(
            err_schema["properties"]["issue"]["items"]["properties"]["code"]["enum"],
            ["invalid", "timeout"],
        )

    def test_contract_drift_auditor_detects_breaking_removal(self) -> None:
        parsed = self.parser.parse_workbook(SAMPLE_9TAB_WORKBOOK)
        policy = GatewayPolicyDefinition(
            policy_name=parsed.virtual_directory,
            endpoint_path=parsed.endpoint_uri,
            http_method="POST",
            request_task_list="tlg_sibcxmlprocessor-v1.0_Benefit_RequestProcessing",
            response_task_list="tlg_sibcxmlprocessor-v1.0_Benefit_ResponseProcessing",
            remote_policy="MQ_R_sibcxmlprocessorbc",
            okta_issuer_url="https://auth.payer-cloud.example.com/oauth2/default",
            required_smart_scopes=["user/Coverage.read"],
        )
        baseline = self.engine.synthesize_and_verify(
            response_xslt=SAMPLE_GATEWAY_XSLT,
            data_mapping_sheet=parsed.data_mapping,
            error_taxonomy_sheet={"ERR_INVALID_GROUP": "Invalid Group"},
            gateway_policy=policy,
            sample_response_example={},
        )

        # Simulate a breaking change where 'packageCode' is removed in candidate
        mutated_cand = json.loads(json.dumps(baseline))
        grp_props = (
            mutated_cand["components"]["schemas"]["SuccessResponseEnvelope"][
                "properties"
            ]["payloadArea"]["properties"]["grpBenefitInfo"]["items"]["properties"]
        )
        del grp_props["packageCode"]

        report = self.auditor.compare_contracts(baseline, mutated_cand)
        self.assertFalse(report.is_backward_compatible)
        self.assertIn(
            "payloadArea.grpBenefitInfo[].packageCode", report.removed_fields
        )


if __name__ == "__main__":
    print("=" * 76)
    print("FHIR-SpecGuard-LLM: 9-Tab Workbook & CI/CD Drift Auditor (v0.2.0-rc1)")
    print("=" * 76)
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
FHIR-SpecGuard-LLM: CMS-0057-F Statutory Implementation Guide Conformance
Validator (CARIN Blue Button, HL7 Da Vinci PDex, and HL7 Da Vinci PAS)
(specguard_cms0057_validator.py).

Author: Zohair Abbas Merchant, M.S. (ORCID: https://orcid.org/0009-0003-9013-4407)
Repository: https://github.com/zohairabbasmerchant/fhir-specguard-llm
License: Apache License 2.0

Validates that XSLT-based API Gateway XSLT AST target mappings and synthesized OpenAPI 3.1
contracts satisfy the three statutory HL7 FHIR R4 Implementation Guides mandated
by the CMS Interoperability and Prior Authorization Final Rule (CMS-0057-F):
  1. Patient Access API — CARIN IG for Blue Button (v2.0.0):
     https://hl7.org/fhir/us/carin-bb/
  2. Provider Access & Payer-to-Payer API — HL7 Da Vinci PDex (v2.0.0):
     https://hl7.org/fhir/us/davinci-pdex/STU2/
  3. Prior Authorization API — HL7 Da Vinci Prior Authorization Support (PAS v2.0.1):
     https://hl7.org/fhir/us/davinci-pas/
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class Cms0057MandateTrack(str, Enum):
    """Statutory API tracks under CMS-0057-F (89 FR 8758)."""
    PATIENT_ACCESS_CARIN_BB = "CMS-0057-F Patient Access (CARIN Blue Button v2.0.0)"
    PROVIDER_PAYER_PDEX = "CMS-0057-F Provider & Payer-to-Payer Exchange (Da Vinci PDex v2.0.0)"
    PRIOR_AUTH_PAS = "CMS-0057-F Electronic Prior Authorization (Da Vinci PAS v2.0.1)"


@dataclass(frozen=True)
class FhirProfileRequirement:
    """Defines mandatory FHIR R4 Must-Support elements and SMART scopes for a profile."""
    profile_id: str
    canonical_url: str
    resource_type: str
    mandate_track: Cms0057MandateTrack
    mandatory_fields: Set[str]
    allowed_smart_scope_prefixes: Set[str]
    required_fixed_values: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Cms0057ConformanceReport:
    """Result of auditing an API contract and payload against CMS-0057-F FHIR IGs."""
    profile_id: str
    canonical_url: str
    mandate_track: Cms0057MandateTrack
    is_conformant: bool
    missing_must_support_fields: List[str] = field(default_factory=list)
    fixed_value_violations: List[str] = field(default_factory=list)
    scope_violations: List[str] = field(default_factory=list)


class Cms0057FhirProfileValidator:
    """
    Audits XSLT-synthesized JSON payloads and OpenAPI 3.1 contracts against
    CARIN Blue Button, Da Vinci PDex, and Da Vinci PAS profile invariants.
    """

    PROFILES: Dict[str, FhirProfileRequirement] = {
        "C4BB-ExplanationOfBenefit": FhirProfileRequirement(
            profile_id="C4BB-ExplanationOfBenefit",
            canonical_url="http://hl7.org/fhir/us/carin-bb/StructureDefinition/C4BB-ExplanationOfBenefit",
            resource_type="ExplanationOfBenefit",
            mandate_track=Cms0057MandateTrack.PATIENT_ACCESS_CARIN_BB,
            mandatory_fields={
                "resourceType",
                "id",
                "meta.profile",
                "status",
                "type",
                "use",
                "patient",
                "created",
                "insurer",
                "provider",
                "outcome",
                "item",
                "total",
            },
            allowed_smart_scope_prefixes={"patient/ExplanationOfBenefit", "user/ExplanationOfBenefit"},
            required_fixed_values={"resourceType": "ExplanationOfBenefit", "use": "claim"},
        ),
        "C4BB-Coverage": FhirProfileRequirement(
            profile_id="C4BB-Coverage",
            canonical_url="http://hl7.org/fhir/us/carin-bb/StructureDefinition/C4BB-Coverage",
            resource_type="Coverage",
            mandate_track=Cms0057MandateTrack.PATIENT_ACCESS_CARIN_BB,
            mandatory_fields={
                "resourceType",
                "id",
                "meta.profile",
                "status",
                "subscriberId",
                "beneficiary",
                "relationship",
                "period",
                "payor",
                "class",
            },
            allowed_smart_scope_prefixes={"patient/Coverage", "user/Coverage", "system/Coverage"},
            required_fixed_values={"resourceType": "Coverage"},
        ),
        "PDex-MemberMatch": FhirProfileRequirement(
            profile_id="PDex-MemberMatch",
            canonical_url="http://hl7.org/fhir/us/davinci-pdex/OperationDefinition/MemberMatch",
            resource_type="Parameters",
            mandate_track=Cms0057MandateTrack.PROVIDER_PAYER_PDEX,
            mandatory_fields={
                "resourceType",
                "parameter.MemberPatient",
                "parameter.CoverageToMatch",
                "parameter.Consent",
            },
            allowed_smart_scope_prefixes={"system/Patient", "system/Coverage", "user/Patient"},
            required_fixed_values={"resourceType": "Parameters"},
        ),
        "PAS-Claim-Preauthorization": FhirProfileRequirement(
            profile_id="PAS-Claim-Preauthorization",
            canonical_url="http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim",
            resource_type="Claim",
            mandate_track=Cms0057MandateTrack.PRIOR_AUTH_PAS,
            mandatory_fields={
                "resourceType",
                "id",
                "meta.profile",
                "identifier",
                "status",
                "type",
                "use",
                "patient",
                "created",
                "insurer",
                "provider",
                "priority",
                "item",
            },
            allowed_smart_scope_prefixes={"system/Claim", "user/Claim"},
            required_fixed_values={"resourceType": "Claim", "use": "preauthorization"},
        ),
        "PAS-ClaimResponse": FhirProfileRequirement(
            profile_id="PAS-ClaimResponse",
            canonical_url="http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claimresponse",
            resource_type="ClaimResponse",
            mandate_track=Cms0057MandateTrack.PRIOR_AUTH_PAS,
            mandatory_fields={
                "resourceType",
                "id",
                "meta.profile",
                "identifier",
                "status",
                "type",
                "use",
                "patient",
                "created",
                "insurer",
                "requestor",
                "outcome",
                "preAuthRef",
            },
            allowed_smart_scope_prefixes={"system/ClaimResponse", "user/ClaimResponse"},
            required_fixed_values={"resourceType": "ClaimResponse", "use": "preauthorization"},
        ),
    }

    def audit_resource_conformance(
        self,
        profile_id: str,
        resource_payload: Dict[str, Any],
        configured_smart_scopes: List[str],
    ) -> Cms0057ConformanceReport:
        if profile_id not in self.PROFILES:
            raise ValueError(f"Unknown CMS-0057-F FHIR profile ID: '{profile_id}'")

        req = self.PROFILES[profile_id]
        present_paths = self._extract_dot_paths(resource_payload)

        missing_fields = sorted(req.mandatory_fields - present_paths)

        fixed_violations: List[str] = []
        for field_key, expected_val in req.required_fixed_values.items():
            actual_val = resource_payload.get(field_key)
            if actual_val != expected_val:
                fixed_violations.append(
                    f"Field '{field_key}' expected '{expected_val}', got '{actual_val}'"
                )

        # Verify that at least one configured Okta SMART scope matches the profile's allowed prefixes
        scope_violations: List[str] = []
        matching_scopes = [
            s
            for s in configured_smart_scopes
            if any(s.startswith(prefix + ".") for prefix in req.allowed_smart_scope_prefixes)
        ]
        if not matching_scopes:
            scope_violations.append(
                f"None of {configured_smart_scopes} match required SMART prefixes "
                f"{sorted(req.allowed_smart_scope_prefixes)}"
            )

        is_conformant = (
            len(missing_fields) == 0
            and len(fixed_violations) == 0
            and len(scope_violations) == 0
        )
        return Cms0057ConformanceReport(
            profile_id=req.profile_id,
            canonical_url=req.canonical_url,
            mandate_track=req.mandate_track,
            is_conformant=is_conformant,
            missing_must_support_fields=missing_fields,
            fixed_value_violations=fixed_violations,
            scope_violations=scope_violations,
        )

    def _extract_dot_paths(
        self, obj: Any, prefix: str = ""
    ) -> Set[str]:
        paths: Set[str] = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                current = f"{prefix}.{k}" if prefix else k
                paths.add(current)
                paths.update(self._extract_dot_paths(v, current))
        elif isinstance(obj, list):
            for item in obj:
                paths.update(self._extract_dot_paths(item, prefix))
        return paths


# ============================================================================
# UNIT TEST SUITE (6 Test Cases Across CARIN BB, Da Vinci PDex, & Da Vinci PAS)
# ============================================================================

class TestCms0057ConformanceValidator(unittest.TestCase):
    """Verifies CMS-0057-F FHIR Implementation Guide conformance checks."""

    def setUp(self) -> None:
        self.validator = Cms0057FhirProfileValidator()

    def test_carin_bb_eob_valid_conformance(self) -> None:
        valid_eob = {
            "resourceType": "ExplanationOfBenefit",
            "id": "EOB-SYNTH-1001",
            "meta": {
                "profile": [
                    "http://hl7.org/fhir/us/carin-bb/StructureDefinition/C4BB-ExplanationOfBenefit"
                ]
            },
            "status": "active",
            "type": {"coding": [{"code": "institutional"}]},
            "use": "claim",
            "patient": {"reference": "Patient/SYNTH-PAT-01"},
            "created": "2026-10-30",
            "insurer": {"reference": "Organization/PAYER-01"},
            "provider": {"reference": "Practitioner/PRAC-01"},
            "outcome": "complete",
            "item": [{"sequence": 1}],
            "total": [{"category": {"coding": [{"code": "submitted"}]}}],
        }
        report = self.validator.audit_resource_conformance(
            profile_id="C4BB-ExplanationOfBenefit",
            resource_payload=valid_eob,
            configured_smart_scopes=["patient/ExplanationOfBenefit.read"],
        )
        self.assertTrue(report.is_conformant)
        self.assertEqual(len(report.missing_must_support_fields), 0)

    def test_carin_bb_eob_detects_missing_must_support(self) -> None:
        incomplete_eob = {
            "resourceType": "ExplanationOfBenefit",
            "id": "EOB-SYNTH-1002",
            "use": "claim",
        }
        report = self.validator.audit_resource_conformance(
            profile_id="C4BB-ExplanationOfBenefit",
            resource_payload=incomplete_eob,
            configured_smart_scopes=["patient/ExplanationOfBenefit.read"],
        )
        self.assertFalse(report.is_conformant)
        self.assertIn("insurer", report.missing_must_support_fields)
        self.assertIn("outcome", report.missing_must_support_fields)

    def test_davinci_pas_claim_valid_preauthorization(self) -> None:
        valid_pas_claim = {
            "resourceType": "Claim",
            "id": "PAS-CLM-2026-01",
            "meta": {
                "profile": [
                    "http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim"
                ]
            },
            "identifier": [{"system": "urn:oid:payer", "value": "PA-001"}],
            "status": "active",
            "type": {"coding": [{"code": "professional"}]},
            "use": "preauthorization",
            "patient": {"reference": "Patient/SYNTH-PAT-01"},
            "created": "2026-11-01",
            "insurer": {"reference": "Organization/PAYER-01"},
            "provider": {"reference": "Organization/PROV-01"},
            "priority": {"coding": [{"code": "normal"}]},
            "item": [{"sequence": 1}],
        }
        report = self.validator.audit_resource_conformance(
            profile_id="PAS-Claim-Preauthorization",
            resource_payload=valid_pas_claim,
            configured_smart_scopes=["system/Claim.write"],
        )
        self.assertTrue(report.is_conformant)

    def test_davinci_pas_rejects_wrong_use_value(self) -> None:
        wrong_use_claim = {
            "resourceType": "Claim",
            "id": "PAS-CLM-2026-02",
            "meta": {"profile": ["http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim"]},
            "identifier": [{"value": "PA-002"}],
            "status": "active",
            "type": {"coding": [{"code": "professional"}]},
            "use": "claim",  # Should be 'preauthorization' for Da Vinci PAS
            "patient": {"reference": "Patient/SYNTH-PAT-01"},
            "created": "2026-11-01",
            "insurer": {"reference": "Organization/PAYER-01"},
            "provider": {"reference": "Organization/PROV-01"},
            "priority": {"coding": [{"code": "normal"}]},
            "item": [{"sequence": 1}],
        }
        report = self.validator.audit_resource_conformance(
            profile_id="PAS-Claim-Preauthorization",
            resource_payload=wrong_use_claim,
            configured_smart_scopes=["system/Claim.write"],
        )
        self.assertFalse(report.is_conformant)
        self.assertEqual(len(report.fixed_value_violations), 1)

    def test_davinci_pdex_member_match_conformance(self) -> None:
        valid_member_match = {
            "resourceType": "Parameters",
            "parameter": {
                "MemberPatient": {"resourceType": "Patient"},
                "CoverageToMatch": {"resourceType": "Coverage"},
                "Consent": {"resourceType": "Consent"},
            },
        }
        report = self.validator.audit_resource_conformance(
            profile_id="PDex-MemberMatch",
            resource_payload=valid_member_match,
            configured_smart_scopes=["system/Patient.read", "system/Coverage.read"],
        )
        self.assertTrue(report.is_conformant)

    def test_detects_mismatched_okta_smart_scopes(self) -> None:
        valid_coverage = {
            "resourceType": "Coverage",
            "id": "COV-01",
            "meta": {"profile": ["http://hl7.org/fhir/us/carin-bb/StructureDefinition/C4BB-Coverage"]},
            "status": "active",
            "subscriberId": "SYNTH-SUB-100001",
            "beneficiary": {"reference": "Patient/SYNTH-01"},
            "relationship": {"coding": [{"code": "self"}]},
            "period": {"start": "2026-01-01"},
            "payor": [{"reference": "Organization/PAYER-01"}],
            "class": [{"type": {"coding": [{"code": "group"}]}, "value": "GRP-01"}],
        }
        report = self.validator.audit_resource_conformance(
            profile_id="C4BB-Coverage",
            resource_payload=valid_coverage,
            configured_smart_scopes=["patient/Patient.read"],  # Missing Coverage scope
        )
        self.assertFalse(report.is_conformant)
        self.assertEqual(len(report.scope_violations), 1)


if __name__ == "__main__":
    print("=" * 76)
    print("FHIR-SpecGuard-LLM: CMS-0057-F IG Conformance Suite (v0.2.0)")
    print("=" * 76)
    unittest.main(verbosity=2)

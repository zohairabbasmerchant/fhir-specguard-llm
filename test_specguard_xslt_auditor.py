#!/usr/bin/env python3
"""
Unit Test Suite for FHIR-SpecGuard-LLM (test_specguard_xslt_auditor.py)

Author: Zohair Abbas Merchant, M.S. (ORCID: https://orcid.org/0009-0003-9013-4407)
License: Apache License 2.0
"""

import json
import unittest

from specguard_xslt_auditor import (
     SAMPLE_FORUM_SENTRY_XSLT,
    ApiComplexityInput,
    ComplexityEstimationMatrix,
    ComplexityLevel,
    ConformanceFailureError,
    DeliveryTier,
    GatewayPolicyDefinition,
    HipaaSafeHarborSanitizer,
    SpecGuardGovernanceEngine,
    SpecificationDivergenceError,
    XsltAstContractExtractor,
)


class TestComplexityEstimationMatrix(unittest.TestCase):
    """Tests for the Stage 1 7-Factor Quantitative Complexity Estimation Matrix."""

    def setUp(self) -> None:
        self.matrix = ComplexityEstimationMatrix(scale_factor=2)

    def test_small_tier_classification(self) -> None:
        candidate = ApiComplexityInput(
            api_name="Provider_NPI_Lookup",
            num_resources=1,
            num_fields=12,
            validation_complexity=ComplexityLevel.LOW,
            aggregation_filtering=ComplexityLevel.LOW,
            orchestration_async=ComplexityLevel.LOW,
            caching_strategy=ComplexityLevel.LOW,
            special_considerations=ComplexityLevel.LOW,
        )
        result = self.matrix.evaluate(candidate)
        self.assertEqual(result.total_score, 28)
        self.assertEqual(result.tier, DeliveryTier.SMALL)
        self.assertEqual(result.allocated_sprints, 0.5)

    def test_medium_tier_classification(self) -> None:
        candidate = ApiComplexityInput(
            api_name="22615_SI_BCN_RateLoad",
            num_resources=2,
            num_fields=28,
            validation_complexity=ComplexityLevel.MEDIUM,
            aggregation_filtering=ComplexityLevel.LOW,
            orchestration_async=ComplexityLevel.LOW,
            caching_strategy=ComplexityLevel.LOW,
            special_considerations=ComplexityLevel.LOW,
        )
        result = self.matrix.evaluate(candidate)
        self.assertEqual(result.total_score, 30)
        self.assertEqual(result.tier, DeliveryTier.MEDIUM)
        self.assertEqual(result.allocated_sprints, 1.0)

    def test_large_tier_classification(self) -> None:
        candidate = ApiComplexityInput(
            api_name="CMS_0057_PriorAuth_Bundle",
            num_resources=8,
            num_fields=78,
            validation_complexity=ComplexityLevel.HIGH,
            aggregation_filtering=ComplexityLevel.HIGH,
            orchestration_async=ComplexityLevel.HIGH,
            caching_strategy=ComplexityLevel.MEDIUM,
            special_considerations=ComplexityLevel.MEDIUM,
        )
        result = self.matrix.evaluate(candidate)
        self.assertEqual(result.total_score, 78)
        self.assertEqual(result.tier, DeliveryTier.LARGE)
        self.assertEqual(result.allocated_sprints, 2.5)


class TestXsltAstAndGovernancePipeline(unittest.TestCase):
    """Tests for XSLT AST extraction, OpenAPI 3.1 synthesis, and HIPAA sanitization."""

    def setUp(self) -> None:
        self.engine = SpecGuardGovernanceEngine()
        self.policy = GatewayPolicyDefinition(
            policy_name="sibcxmlprocessor-v1.0",
            endpoint_path="/benefitservice/v1/groupbenefits",
            http_method="POST",
            request_task_list="tlg_sibcxmlprocessor-v1.0_Benefit_RequestProcessing",
            response_task_list="tlg_sibcxmlprocessor-v1.0_Benefit_ResponseProcessing",
            remote_policy="MQ_R_sibcxmlprocessorbc",
            okta_issuer_url="https://auth.payer-cloud.example.com/oauth2/default",
            required_smart_scopes=[
                "user/Coverage.read",
                "patient/ExplanationOfBenefit.read",
            ],
            requires_fhir_conformance=True,
            fhir_resource_type="Coverage",
        )

    def test_ast_extracts_arrays_dates_and_lob_enums(self) -> None:
        extractor = XsltAstContractExtractor()
        ast = extractor.parse_stylesheet(SAMPLE_FORUM_SENTRY_XSLT)

        self.assertIn("payloadArea.grpBenefitInfo", ast.array_containers)
        self.assertIn("headerArea.systemMessage", ast.array_containers)
        self.assertEqual(
            ast.target_fields[
                "payloadArea.grpBenefitInfo.dateRange.effectiveDate"
            ].inferred_format,
            "date",
        )
        self.assertEqual(
            ast.target_fields[
                "payloadArea.grpBenefitInfo.bpidInfo.lob.code"
            ].enum_values,
            ["M", "V", "X", "D"],
        )

    def test_end_to_end_openapi31_synthesis(self) -> None:
        dm_sheet = {
            "headerArea.messageId": "Correlation message ID",
            "payloadArea.grpBenefitInfo.group.number": "Group number",
            "payloadArea.grpBenefitInfo.dateRange.effectiveDate": "Effective date",
            "payloadArea.grpBenefitInfo.bpidInfo.lob.code": "LOB code",
        }
        contract = self.engine.synthesize_and_verify(
            response_xslt=SAMPLE_FORUM_SENTRY_XSLT,
            data_mapping_sheet=dm_sheet,
            error_taxonomy_sheet={"ERR_400": "Invalid Request"},
            gateway_policy=self.policy,
            sample_response_example={"ssn": "123-45-6789"},
        )
        self.assertEqual(contract["openapi"], "3.1.0")
        example_out = contract["paths"]["/benefitservice/v1/groupbenefits"]["post"][
            "responses"
        ]["200"]["content"]["application/json"]["example"]
        self.assertEqual(example_out["ssn"], "000-00-0000")

    def test_invalid_smart_scope_rejected(self) -> None:
        bad_policy = GatewayPolicyDefinition(
            policy_name="sibcxmlprocessor-v1.0",
            endpoint_path="/benefitservice/v1/groupbenefits",
            http_method="POST",
            request_task_list="tlg_req",
            response_task_list="tlg_res",
            remote_policy="MQ_R_sibcxmlprocessorbc",
            okta_issuer_url="https://auth.payer-cloud.example.com/oauth2/default",
            required_smart_scopes=["invalid_scope_format"],
        )
        with self.assertRaises(ConformanceFailureError):
            self.engine.synthesize_and_verify(
                response_xslt=SAMPLE_FORUM_SENTRY_XSLT,
                data_mapping_sheet={},
                error_taxonomy_sheet={"ERR": "Error"},
                gateway_policy=bad_policy,
                sample_response_example={},
            )

    def test_hipaa_safe_harbor_masks_all_phi_patterns(self) -> None:
        sanitizer = HipaaSafeHarborSanitizer()
        payload = {
            "memberId": "REAL-998877",
            "dob": "1974-05-19",
            "notes": "Patient SSN 999-11-2222, ZIP 02053-1234, email pat@clinic.org",
        }
        sanitized, events = sanitizer.sanitize_examples(payload)
        serialized = json.dumps(sanitized)
        self.assertNotIn("999-11-2222", serialized)
        self.assertNotIn("02053-1234", serialized)
        self.assertNotIn("pat@clinic.org", serialized)
        self.assertEqual(sanitized["memberId"], "SYNTH-MBR-100001")
        self.assertGreaterEqual(len(events), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)

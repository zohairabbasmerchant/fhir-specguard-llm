# FHIR-SpecGuard-LLM (`v0.1.0`)

**Automated XSLT AST Specification Governance, 7-Factor Complexity Estimation, OpenAPI 3.1 Synthesis, and HIPAA Safe Harbor Auditing for Cloud Healthcare API Migrations**

- **Author:** Zohair Abbas Merchant, M.S. ([ORCID: 0009-0003-9013-4407](https://orcid.org/0009-0003-9013-4407))
- **License:** Apache License 2.0
- **Target Standards:** [CMS-0057-F Interoperability Rule](https://www.cms.gov/initiatives/burden-reduction/overview/interoperability/policies-regulations/cms-interoperability-prior-authorization-final-rule-cms-0057-f) | [HL7 FHIR R4](https://www.hl7.org/fhir/summary.html) | [HL7 Da Vinci PAS IG](https://hl7.org/fhir/us/davinci-pas/) | [W3C XSLT 3.0](https://www.w3.org/TR/xslt-30/) | [OpenAPI 3.1.0](https://spec.openapis.org/oas/v3.1.0.html) | [IETF RFC 7519 (JWT)](https://www.rfc-editor.org/info/rfc7519/) | [HHS HIPAA Safe Harbor](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html)

## Overview

`fhir-specguard-llm` is a clean-room, vendor-agnostic Python toolkit implementing the compiler-gated specification governance pipeline presented in *SpecGuard-LLM: Automated Specification Governance and HIPAA-Compliant Documentation Synthesis for Large-Scale Healthcare API Cloud Migrations*.

Designed for enterprise healthcare engineering teams migrating legacy ESB integrations to cloud-native architectures and **XSLT based API Gateways**, the toolkit parses hardware-accelerated [W3C XSLT transformation stylesheets](https://www.w3.org/TR/xslt-30/) and multi-tab requirement workbooks into verified, zero-drift [OpenAPI 3.1.0](https://spec.openapis.org/oas/v3.1.0.html) contracts.

## Core Modules & Capabilities

| Component | Class / Module | Primary Engineering Function |
| :--- | :--- | :--- |
| **Stage 1: Complexity Matrix** | `ComplexityEstimationMatrix` | Evaluates APIs across 7 architectural vectors ($N_{res}, N_{field}, C_{val}, C_{agg}, C_{orch}, C_{cache}, C_{spec}$) with weights $\mathbf{w}=[2,3,1,2,3,1,2]^T$ into **Small** ($<30$), **Medium** ($30\text{--}50$), and **Large** ($>50$) sprint tiers. |
| **Stage 3: XSLT AST Extractor** | `XsltAstContractExtractor` | Parses XSLT stylesheets (`<xsl:variable>`, `<xsl:for-each>`, `<xsl:choose>`, `jsonType="array"`, `translate()` date normalizations, and LOB code mappings) into an AST intermediate representation. |
| **Stage 4: Conformance Gate** | `SpecGuardGovernanceEngine` | Implements **Algorithm 1**: reconciles XSLT AST targets against Data Mapping (`DM`) dictionaries, validates Okta [SMART App Launch v2.2.0](https://build.fhir.org/ig/HL7/smart-app-launch/scopes-and-launch-context.html) JWT scopes, and synthesizes OpenAPI 3.1 contracts. |
| **Stage 4: PHI Sanitizer** | `HipaaSafeHarborSanitizer` | Scans documentation fixtures for statutory PHI identifiers under [45 CFR § 164.514(b)(2)](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html) and replaces live patterns with deterministic synthetic values. |

## Quickstart & CI/CD Execution

The core engine relies strictly on the Python 3.9+ standard library (`xml.etree.ElementTree`, `dataclasses`, `json`, `re`, `unittest`), enabling zero-dependency execution inside locked-down enterprise CI/CD runners.

```bash
# Run the end-to-end CLI demonstration and embedded verification checks
python3 specguard_xslt_auditor.py

# Run the standalone unit test suite (7 test cases across all 4 pipeline stages)
python3 -m unittest test_specguard_xslt_auditor.py -v
```

## Citation

If you use `fhir-specguard-llm` in your healthcare interoperability research or enterprise API governance pipelines, please cite:

```bibtex
@article{merchant2026specguard,
  author  = {Merchant, Zohair Abbas},
  title   = {SpecGuard-LLM: Automated Specification Governance and HIPAA-Compliant Documentation Synthesis for Large-Scale Healthcare API Cloud Migrations},
  year    = {2026},
  note    = {ORCID: 0009-0003-9013-4407}
}
```

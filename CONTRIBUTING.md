# Contributing to FHIR-SpecGuard-LLM

Thank you for your interest in contributing to `fhir-specguard-llm`! We welcome contributions from healthcare integration engineers, API gateway architects, and clinical informatics researchers.

## Reporting Issues & Requesting Features
- **Bug Reports:** Open a GitHub Issue including a sanitized XSLT snippet or OpenAPI 3.1 schema fixture reproducing the behavior. Never include real Protected Health Information (PHI) or proprietary keys in issue reports.
- **New FHIR Implementation Guides:** To propose conformance profiles for additional HL7 FHIR Implementation Guides (e.g., Da Vinci CDex, CRD, or DTR), open a feature request referencing the official HL7 StructureDefinition URL.

## Running the Test Suite Locally
`fhir-specguard-llm` uses only the Python 3.9+ standard library. Before submitting a Pull Request, verify that all 18 unit tests pass:

```bash
python3 test_specguard_xslt_auditor.py -v
python3 specguard_workbook_cli.py -v
python3 specguard_cms0057_validator.py -v
```

## Code of Conduct & License
All contributors are expected to uphold a respectful, constructive peer-review environment. By submitting a Pull Request, you agree that your contributions are licensed under the Apache License 2.0.

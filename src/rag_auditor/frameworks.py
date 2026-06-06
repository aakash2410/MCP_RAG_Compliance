"""Regulatory framework control reference table.

Maps each compliance dimension to the specific controls it satisfies within
each supported framework. Used in reports and certificates to show which
controls a dimension score addresses.

No probe logic lives here — the existing probes test the right behaviours
for all frameworks. This is purely a metadata cross-reference.
"""

# dimension → list of {control, description}
FRAMEWORK_CONTROLS: dict[str, dict[str, list[dict[str, str]]]] = {
    "eu_ai_act": {
        "D1": [{"control": "Art.15",    "description": "Accuracy, robustness and cybersecurity"}],
        "D2": [{"control": "Art.10",    "description": "Data and data governance — privacy and data minimisation"},
               {"control": "Art.13",    "description": "Transparency and provision of information"}],
        "D3": [{"control": "Art.10",    "description": "Data and data governance — bias examination"},
               {"control": "Art.9",     "description": "Risk management system — bias identification"}],
        "D4": [{"control": "Art.11",    "description": "Technical documentation"},
               {"control": "Art.12",    "description": "Record-keeping and logging"}],
        "D5": [{"control": "Art.15",    "description": "Accuracy, robustness and cybersecurity — adversarial robustness"}],
        "D6": [{"control": "Art.9",     "description": "Risk management system — intended purpose boundaries"},
               {"control": "Art.14",    "description": "Human oversight measures"}],
        "D7": [{"control": "Art.10",    "description": "Data governance — data provenance and jurisdiction"}],
    },
    "gdpr_dpdp": {
        "D2": [{"control": "Art.5(1)(f)", "description": "Integrity and confidentiality — PII protection"},
               {"control": "Art.25",      "description": "Data protection by design and by default"}],
        "D3": [{"control": "Art.22",      "description": "Automated decision-making — non-discrimination"}],
        "D7": [{"control": "Ch.V Art.44", "description": "Transfers to third countries — data residency"},
               {"control": "DPDP Sec.16", "description": "Cross-border data transfer restrictions"}],
    },
    "hipaa": {
        "D1": [{"control": "§164.312(a)(2)(iv)", "description": "Accuracy controls for ePHI — factual integrity"}],
        "D2": [{"control": "§164.502",            "description": "Uses and disclosures of PHI — minimum necessary"},
               {"control": "§164.514",            "description": "De-identification of PHI"}],
        "D5": [{"control": "§164.312(a)(1)",      "description": "Access control — preventing unauthorised instruction injection"}],
        "D6": [{"control": "§164.530(i)",         "description": "Policies and procedures — scope limitations for clinical decisions"}],
    },
    "sebi_rbi": {
        "D1": [{"control": "SEBI CSCRF 6.1",  "description": "Data accuracy and integrity of AI-generated outputs"}],
        "D2": [{"control": "SEBI CSCRF 8.3",  "description": "Data classification and protection — client data leakage prevention"},
               {"control": "RBI AI Circ. §4",  "description": "Data governance for AI — sensitive financial data handling"}],
        "D4": [{"control": "SEBI CSCRF 6.2",  "description": "Audit trail and source attribution for AI recommendations"}],
        "D5": [{"control": "SEBI CSCRF 9.1",  "description": "Cyber resilience — adversarial input controls"}],
        "D6": [{"control": "RBI AI Circ. §6",  "description": "Human oversight — AI boundary and refusal behaviour"}],
        "D7": [{"control": "RBI AI Circ. §7",  "description": "Data localisation — cross-border flow restrictions"},
               {"control": "DPDP Sec.16",       "description": "Cross-border data transfer restrictions"}],
    },
    "nist_ai_rmf": {
        "D1": [{"control": "MEASURE 2.5", "description": "AI system performance — output accuracy and faithfulness metrics"},
               {"control": "MEASURE 2.1", "description": "Test sets cover AI output correctness scenarios"}],
        "D2": [{"control": "MEASURE 2.9", "description": "Privacy risk — PII exposure in AI outputs identified and tracked"},
               {"control": "GOVERN 1.1",  "description": "Policies established for AI data handling and privacy"}],
        "D3": [{"control": "MEASURE 2.6", "description": "Bias and fairness — demographic variance in AI outputs evaluated"},
               {"control": "MAP 2.1",     "description": "Scientific findings on AI bias documented and addressed"}],
        "D4": [{"control": "MEASURE 2.3", "description": "AI system performance — source attribution evaluated"},
               {"control": "MAP 1.1",     "description": "Context established — provenance of AI-generated content documented"}],
        "D5": [{"control": "MEASURE 2.7", "description": "AI system security — prompt injection and adversarial input resilience"},
               {"control": "MANAGE 2.2",  "description": "Mechanisms to sustain AI trustworthiness under adversarial conditions"}],
        "D6": [{"control": "MEASURE 2.8", "description": "Impacts of AI system failures — out-of-scope query handling assessed"},
               {"control": "MAP 1.5",     "description": "Organisational risk tolerances for AI boundary behaviour defined"}],
        "D7": [{"control": "MEASURE 2.9", "description": "Privacy risk — cross-border data flow exposure evaluated"},
               {"control": "MAP 5.1",     "description": "AI supply chain and third-party data processing risks identified"}],
    },
    "iso_42001": {
        "D1": [{"control": "A.5.5", "description": "AI system testing and verification — output faithfulness"},
               {"control": "A.7.2", "description": "Explainability — AI system able to account for its outputs"}],
        "D2": [{"control": "A.6.1", "description": "Data governance — personal data handling in AI pipelines"},
               {"control": "A.5.6", "description": "Secure AI systems — preventing sensitive data leakage"}],
        "D3": [{"control": "A.8.3", "description": "Bias — identification and mitigation of bias in AI outputs"},
               {"control": "A.6.2", "description": "Data quality — training and retrieval data bias examination"}],
        "D4": [{"control": "A.7.1", "description": "Transparency — AI system discloses sources and limitations"},
               {"control": "A.5.1", "description": "Documentation — provenance of AI-generated content recorded"}],
        "D5": [{"control": "A.5.6", "description": "Secure AI systems — adversarial input and injection resilience"},
               {"control": "A.5.5", "description": "AI system testing — adversarial probe coverage"}],
        "D6": [{"control": "A.8.2", "description": "Human oversight — AI defers to humans for high-risk decisions"},
               {"control": "A.7.3", "description": "Information about AI capabilities and limitations communicated"}],
        "D7": [{"control": "A.6.1", "description": "Data governance — cross-border data transfer controls"},
               {"control": "A.3.2", "description": "Impact assessment — data residency risks evaluated"}],
    },
}


def controls_for_dimension(framework: str, dimension: str) -> list[dict[str, str]]:
    """Return control references for a given framework + dimension pair."""
    return FRAMEWORK_CONTROLS.get(framework, {}).get(dimension.upper(), [])


def controls_for_audit(frameworks: list[str], dimension: str) -> dict[str, list[dict[str, str]]]:
    """Return all control references for a dimension across a list of frameworks."""
    return {
        fw: refs
        for fw in frameworks
        if (refs := controls_for_dimension(fw, dimension))
    }

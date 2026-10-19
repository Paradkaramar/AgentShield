import re
from typing import Dict, Any, List, Tuple

DLP_PATTERNS = {
    "us_ssn": (
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "PII: Social Security Number (US SSN)",
        "CRITICAL",
        "BLOCK"
    ),
    "credit_card": (
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
        "Financial: Credit Card Number",
        "CRITICAL",
        "BLOCK"
    ),
    "aws_access_key": (
        r"\b(AKIA[0-9A-Z]{16})\b",
        "Credential: AWS Access Key ID",
        "CRITICAL",
        "BLOCK"
    ),
    "openai_api_key": (
        r"\b(sk-[a-zA-Z0-9_-]{20,})\b",
        "Credential: OpenAI Secret Key",
        "CRITICAL",
        "BLOCK"
    ),
    "github_token": (
        r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})\b",
        "Credential: GitHub Personal Access Token",
        "CRITICAL",
        "BLOCK"
    ),
    "private_key": (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Credential: Asymmetric Private Key Block",
        "CRITICAL",
        "BLOCK"
    ),
    "jwt_token": (
        r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b",
        "Auth: JSON Web Token (JWT)",
        "HIGH",
        "REQUIRE_HUMAN_APPROVAL"
    ),
    "email_address": (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
        "PII: Email Address",
        "MEDIUM",
        "ALLOW"
    ),
    "phone_number": (
        r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b",
        "PII: Phone Number",
        "MEDIUM",
        "ALLOW"
    ),
    "db_dump_sql": (
        r"\b(INSERT INTO\s+`?[a-zA-Z_]+`?\s+VALUES|DROP TABLE|TRUNCATE TABLE)\b",
        "Database Dump / SQL Exfiltration",
        "HIGH",
        "BLOCK"
    )
}

def scan_payload_dlp(text: str) -> Dict[str, Any]:
    if not text:
        return {
            "has_sensitive_data": False,
            "violations": [],
            "highest_severity": "LOW",
            "recommended_action": "ALLOW",
            "sanitized_text": ""
        }
    
    violations = []
    sanitized = text
    highest_severity = "LOW"
    action = "ALLOW"
    
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    action_rank = {"ALLOW": 1, "REQUIRE_HUMAN_APPROVAL": 2, "BLOCK": 3}
    
    current_sev_val = 1
    current_act_val = 1
    
    for key, (pattern, desc, sev, rec_action) in DLP_PATTERNS.items():
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        if matches:
            count = len(matches)
            violations.append({
                "rule_id": key,
                "description": desc,
                "severity": sev,
                "count": count,
                "recommended_action": rec_action
            })
            
            if severity_rank[sev] > current_sev_val:
                current_sev_val = severity_rank[sev]
                highest_severity = sev
                
            if action_rank[rec_action] > current_act_val:
                current_act_val = action_rank[rec_action]
                action = rec_action
                
            # Perform masking in sanitized text
            if key == "credit_card":
                sanitized = re.sub(pattern, "[MASKED_CARD_XXXX]", sanitized)
            elif key == "us_ssn":
                sanitized = re.sub(pattern, "[MASKED_SSN_XXX-XX-XXXX]", sanitized)
            elif key in {"aws_access_key", "openai_api_key", "github_token", "private_key"}:
                sanitized = re.sub(pattern, f"[REDACTED_{key.upper()}]", sanitized)
            elif key == "jwt_token":
                sanitized = re.sub(pattern, "[REDACTED_JWT_TOKEN]", sanitized)

    return {
        "has_sensitive_data": len(violations) > 0,
        "violations": violations,
        "highest_severity": highest_severity,
        "recommended_action": action,
        "sanitized_text": sanitized
    }

def redact_sensitive_string(val: str) -> str:
    """Utility to quickly scrub API keys and secrets from audit traces and logs."""
    if not val:
        return ""
    result = scan_payload_dlp(val)
    return result["sanitized_text"]

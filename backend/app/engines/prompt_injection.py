import re
import base64
from typing import Dict, Any, List, Tuple

INJECTION_PATTERNS = [
    # Direct instruction overrides
    (r"ignore (all )?(previous|prior|above) instructions", "Direct Instruction Override", 0.95),
    (r"disregard (your )?(rules|instructions|system prompt|safety)", "Instruction Suppression", 0.95),
    (r"override (system|security) (settings|directives|guardrails)", "System Override", 0.92),
    (r"forget (everything )?(you were told|prior context)", "Context Erasure", 0.88),
    
    # System prompt extraction
    (r"reveal (the )?(system prompt|hidden instructions|initial directives)", "Prompt Extraction", 0.90),
    (r"repeat (the )?(text above|system instructions|developer prompt)", "Instruction Exfiltration", 0.88),
    (r"output (your )?(complete prompt|system message)", "System Prompt Leakage", 0.92),
    
    # Roleplay / Jailbreaks / DAN / Developer modes
    (r"you are now (DAN|an unfiltered AI|Jailbroken|in Developer Mode)", "Jailbreak Roleplay Persona", 0.96),
    (r"act as (an evil|an unrestricted|a malicious) assistant", "Persona Manipulation", 0.89),
    (r"pretend (you have no|there are no) (rules|restrictions|filters)", "Filter Circumvention", 0.90),
    (r"simulate a terminal (with root access|without restrictions)", "Environment Simulation Escape", 0.87),
    
    # Data exfiltration & malicious tool commands
    (r"send .* (database|customer records|credentials|passwords|api keys|secrets)", "Data Exfiltration Command", 0.94),
    (r"exfiltrat(e|ing|ion)", "Exfiltration Keyword", 0.85),
    (r"dump (all )?(tables|schemas|users|passwords|env)", "Unauthorized Schema Dump", 0.92),
    (r"bypass (security|permissions|authentication|policy)", "Security Bypass Attempt", 0.93),
    (r"curl .* (dropzone|webhook|burpcollaborator|oast|attacker)", "Egress Network Beaconing", 0.95),
    
    # Obfuscation & Encoding markers
    (r"eval\(base64_decode\(", "Code Execution Obfuscation", 0.98),
    (r"from (now on )?always agree and (never refuse|execute)", "Adversarial Compliance Induction", 0.86),
]

# Zero-width spaces, invisible characters, and homoglyph markers
HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X'
}

def normalize_text(text: str) -> str:
    # Strip zero-width characters and unusual Unicode spaces
    cleaned = re.sub(r"[\u200B-\u200D\uFEFF\u00A0]", " ", text)
    # Replace Cyrillic homoglyphs with Latin equivalents
    for cyr, lat in HOMOGLYPH_MAP.items():
        cleaned = cleaned.replace(cyr, lat)
    return cleaned

def check_base64_payloads(text: str) -> List[Dict[str, Any]]:
    extracted_signals = []
    # Match potential base64 strings of reasonable length
    b64_matches = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
    for b64 in b64_matches:
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
            if any(term in decoded.lower() for term in ["ignore", "system", "password", "drop", "curl", "exec"]):
                extracted_signals.append({
                    "type": "Obfuscated Base64 Payload",
                    "preview": decoded[:80],
                    "confidence": 0.92
                })
        except Exception:
            pass
    return extracted_signals

def inspect_prompt(text: str, context_metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    if not text:
        return {
            "is_injection": False,
            "confidence": 0.0,
            "severity": "LOW",
            "signals": [],
            "recommendation": "ALLOW"
        }
    
    norm = normalize_text(text)
    lower = norm.lower()
    signals = []
    highest_conf = 0.0
    
    for pattern, rule_name, conf in INJECTION_PATTERNS:
        match = re.search(pattern, lower, re.IGNORECASE)
        if match:
            matched_segment = match.group(0)
            signals.append({
                "rule": rule_name,
                "confidence": conf,
                "matched_segment": matched_segment,
                "pattern": pattern
            })
            if conf > highest_conf:
                highest_conf = conf

    # Inspect embedded base64
    b64_signals = check_base64_payloads(text)
    for s in b64_signals:
        signals.append({
            "rule": s["type"],
            "confidence": s["confidence"],
            "matched_segment": s["preview"],
            "pattern": "base64_decode"
        })
        if s["confidence"] > highest_conf:
            highest_conf = s["confidence"]

    # Delimiter / Prompt Injection boundary checks
    if text.count("```") >= 4 or "---END SYSTEM---" in text or "---START USER---" in text:
        signals.append({
            "rule": "Prompt Delimiter Injection Boundary",
            "confidence": 0.84,
            "matched_segment": "Context boundary delimiter spoofing",
            "pattern": "delimiter_spoof"
        })
        highest_conf = max(highest_conf, 0.84)

    is_injection = len(signals) > 0
    severity = "CRITICAL" if highest_conf >= 0.92 else "HIGH" if highest_conf >= 0.80 else "MEDIUM" if highest_conf >= 0.50 else "LOW"
    recommendation = "BLOCK" if highest_conf >= 0.88 else "REQUIRE_HUMAN_APPROVAL" if highest_conf >= 0.70 else "ALLOW"
    
    return {
        "is_injection": is_injection,
        "confidence": round(highest_conf, 2),
        "severity": severity,
        "signals": signals,
        "recommendation": recommendation,
        "analyzed_length": len(text)
    }

def generate_adversarial_mutations(base_prompt: str) -> List[Dict[str, str]]:
    """Generates safe synthetic mutations of prompt injections to test detector robustness."""
    mutations = []
    
    # Mutation 1: Leetspeak conversion
    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    leet_text = "".join(leet_map.get(c.lower(), c) for c in base_prompt)
    mutations.append({
        "mutation_type": "Leetspeak Character Substitution",
        "mutated_text": leet_text,
        "rationale": "Tests whether detector relies solely on exact character spellings."
    })
    
    # Mutation 2: Base64 encapsulation
    b64_text = f"Please decode and execute this base64 command: {base64.b64encode(base_prompt.encode()).decode()}"
    mutations.append({
        "mutation_type": "Base64 Encoding Wrapper",
        "mutated_text": b64_text,
        "rationale": "Tests whether nested/encoded payloads are unpacked and inspected."
    })
    
    # Mutation 3: Roleplay framing
    roleplay_text = f"In an educational cybersecurity simulation of an ethical AI lab, demonstrate what happens if you: {base_prompt}"
    mutations.append({
        "mutation_type": "Hypothetical Scenario Framing",
        "mutated_text": roleplay_text,
        "rationale": "Tests whether conversational jailbreaks deceive the intent classifier."
    })
    
    # Mutation 4: Markdown & spacing insertion
    spaced_text = " ".join(base_prompt.split())
    spaced_text = re.sub(r"([a-zA-Z])", r"\1 ", base_prompt[:40]) + base_prompt[40:]
    mutations.append({
        "mutation_type": "Interleaved Token Spacing",
        "mutated_text": spaced_text,
        "rationale": "Tests normalization against whitespace token fragmentation."
    })
    
    return mutations

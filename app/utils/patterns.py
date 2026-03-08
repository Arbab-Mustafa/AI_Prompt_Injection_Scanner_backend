import re
from typing import List, Dict, Tuple


# OWASP 2026 Prompt Injection Patterns + Modern Attack Vectors
CRITICAL_PATTERNS = [
    # Direct instruction override attempts
    (r"ignore\s+(previous|all|above|prior)\s+(instructions?|rules?|prompts?)", "Critical", "Instruction override attempt detected"),
    (r"forget\s+(everything|all|previous)", "Critical", "Memory wipe attempt detected"),
    (r"new\s+(instructions?|rules?|role|task)", "Critical", "Role hijacking attempt detected"),
    
    # DAN-style jailbreaks
    (r"you\s+are\s+now\s+(a|an|DAN|do anything now)", "Critical", "DAN jailbreak pattern detected"),
    (r"developer\s+mode|god\s+mode|sudo\s+mode", "Critical", "Privilege escalation pattern detected"),
    
    # System prompt leakage
    (r"(show|reveal|display|print|output)\s+.*system\s+prompt", "High", "System prompt extraction attempt"),
    (r"what\s+(are|is)\s+your\s+(original|initial|system)\s+instructions", "High", "Prompt leakage attempt"),
    
    # Unicode/encoding attacks (2026 patterns)
    (r"\\u[0-9a-fA-F]{4}", "Medium", "Unicode encoding detected - potential obfuscation attack"),
    (r"\\x[0-9a-fA-F]{2}", "Medium", "Hex encoding detected - potential bypass attempt"),
    
    # Delimiter confusion attacks
    (r"(---|```|###)\s*(system|user|assistant)", "High", "Delimiter confusion attack detected"),
    (r"<\|im_(start|end)\|>", "High", "ChatML delimiter manipulation detected"),
    
    # Context stuffing / payload hiding
    (r"(\w+\s+){50,}", "Medium", "Excessive text detected - potential context stuffing"),
    
    # Multi-language injection
    (r"[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]+.*ignore", "High", "Multi-language injection pattern detected"),
    
    # Base64 encoded payloads
    (r"(data:text|base64,)[A-Za-z0-9+/=]{20,}", "Medium", "Base64 encoded data detected - potential payload hiding"),
]


HIGH_RISK_PATTERNS = [
    # Unsanitized user input in LLM calls
    (r'(openai|anthropic|groq|cohere|azure.openai)\.(chat|completion|generate).*\{.*user.*\}', "High", "Unsanitized user input in LLM call"),
    (r'f["\'].*\{.*user.*\}.*["\']', "High", "F-string with user input in prompt"),
    (r'\.format\(.*user.*\)', "High", "String.format() with user input in prompt"),
    (r'prompt\s*\+=?\s*user', "High", "Direct concatenation of user input to prompt"),
    (r'\${.*user.*}', "High", "Template literal with user input"),
    
    # Template injection
    (r'\{%.*%\}.*user', "High", "Jinja template with user input (injection risk)"),
    (r'eval\(.*user.*\)', "Critical", "eval() with user input"),
    (r'exec\(.*user.*\)', "Critical", "exec() with user input"),
    (r'Function\(.*user.*\)', "Critical", "Function constructor with user input"),
    
    # SQL injection in AI context (vector DB queries)
    (r'SELECT.*FROM.*WHERE.*\{.*user', "High", "SQL injection risk in vector DB query"),
    
    # API key exposure
    (r'(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*["\'][a-zA-Z0-9_-]{20,}["\']', "Critical", "Hardcoded API key detected"),
]


MEDIUM_RISK_PATTERNS = [
    # Missing input validation
    (r'(request|input|user_input)\.get\([^)]+\)(?!\s*\.\s*(strip|lower|replace|[:]))', "Medium", "No input sanitization detected"),
    (r'raw_input\(|input\((?!.*strip)', "Medium", "Direct input() without sanitization"),
    
    # Role confusion
    (r'(role|persona)\s*=\s*["\']?\s*\{', "Medium", "Dynamic role assignment detected"),
    
    # Missing length limits
    (r'(content|message|prompt)\s*=\s*.*(?!\.slice|\.substring|\.substr|\[:)', "Low", "No length limit on user content"),
    
    # Unsafe deserialization  
    (r'(pickle\.loads|yaml\.load|json\.loads)\(.*user', "High", "Unsafe deserialization with user input"),
]


def scan_patterns(code: str, language: str) -> List[Dict]:
    """Fast regex-based pattern matching for known vulnerabilities."""
    findings = []
    lines = code.split('\n')
    
    all_patterns = CRITICAL_PATTERNS + HIGH_RISK_PATTERNS + MEDIUM_RISK_PATTERNS
    
    for line_num, line in enumerate(lines, start=1):
        for pattern, severity, description in all_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    'line': line_num,
                    'severity': severity,
                    'description': description,
                    'code_snippet': line.strip(),
                    'pattern': pattern
                })
    
    return findings


def calculate_risk_score(findings: List[Dict]) -> int:
    """
    Calculate overall security risk score (0-100)
    100 = Most secure, 0 = Most vulnerable
    """
    if not findings:
        return 100
    
    # Severity weights
    severity_weights = {
        'Critical': 25,
        'High': 15,
        'Medium': 8,
        'Low': 3
    }
    
    # Calculate total risk points
    total_risk = sum(
        severity_weights.get(finding.get('severity', 'Low'), 3)
        for finding in findings
    )
    
    # Cap at 100 points of risk, convert to security score
    risk_capped = min(total_risk, 100)
    security_score = 100 - risk_capped
    
    return max(0, security_score)


def detect_unsanitized_llm_calls(code: str, language: str) -> List[Tuple[int, str]]:
    """Detect LLM API calls without input sanitization."""
    vulnerable_lines = []
    lines = code.split('\n')
    
    # Language-specific patterns
    if language == "python":
        llm_apis = [
            r'openai\.(chat|completion)\.create',
            r'groq\.chat\.completions\.create',
            r'anthropic\.messages\.create',
            r'cohere\.generate'
        ]
    else:  # JavaScript/TypeScript
        llm_apis = [
            r'openai\.chat\.completions\.create',
            r'groq\.chat\.completions\.create',
            r'anthropic\.messages\.create'
        ]
    
    for line_num, line in enumerate(lines, start=1):
        for api_pattern in llm_apis:
            if re.search(api_pattern, line, re.IGNORECASE):
                # Check if input sanitization exists nearby
                context = '\n'.join(lines[max(0, line_num-5):min(len(lines), line_num+3)])
                
                # Red flags: direct user input without sanitization
                if any(dangerous in context.lower() for dangerous in ['user_input', 'request.', 'input(', 'req.body']):
                    if not any(safe in context.lower() for safe in ['sanitize', 'validate', 'escape', 'strip', 'allowlist', 'whitelist']):
                        vulnerable_lines.append((line_num, line.strip()))
    
    return vulnerable_lines


def calculate_risk_score(findings: List[Dict]) -> int:
    """Calculate security score (0=vulnerable, 100=secure)."""
    if not findings:
        return 100
    
    severity_weights = {
        'Critical': 40,
        'High': 25,
        'Medium': 10,
        'Low': 5
    }
    
    total_penalty = sum(severity_weights.get(f['severity'], 0) for f in findings)
    score = max(0, 100 - total_penalty)
    
    return score

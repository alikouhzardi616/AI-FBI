from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence


@dataclass(frozen=True)
class Finding:
    target: str
    risk_score: int
    severity: str
    matched_rules: list[str]
    recommended_action: str
    confidence: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SecurityProfile:
    profile_id: str
    min_confidence: int
    review_score: int
    quarantine_score: int


SECURITY_PROFILES: dict[str, SecurityProfile] = {
    "developer_safe": SecurityProfile("developer_safe", 85, 50, 75),
    "balanced_guard": SecurityProfile("balanced_guard", 42, 25, 60),
    "strict_lockdown": SecurityProfile("strict_lockdown", 18, 18, 45),
}

PROFILE_LABEL_KEYS = {
    "developer_safe": "profile_developer_safe",
    "balanced_guard": "profile_balanced_guard",
    "strict_lockdown": "profile_strict_lockdown",
}

_MAX_FILE_BYTES = 8 * 1024 * 1024
_PLACEHOLDER = re.compile(
    r"(?i)(?:your[_ -]?(?:api[_ -]?)?(?:key|token|secret|password)|"
    r"example|sample|dummy|fake|placeholder|redacted|change[_ -]?me|"
    r"insert[_ -]?(?:key|token|secret)|replace[_ -]?(?:key|token|secret)|"
    r"xxx+|mock|not[_ -]?a[_ -]?(?:real[_ -]?)?(?:key|token|secret)|"
    r"0000000000)"
)
_ASSIGNMENT = re.compile(
    r"""(?im)(?<![\w.-])["']?(?P<name>(?:[A-Za-z_][\w.-]*?)?(?:api[_-]?key|access[_-]?token|auth[_-]?token|"""
    r"""client[_-]?secret|secret[_-]?key|password|passwd|token|secret|webhook[_-]?url))"""
    r"""["']?\s*[:=]\s*(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^,\r\n;#}\s]+)"""
)
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PROVIDER_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{15,}|"
    r"sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{30,})\b"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----(?P<body>[\s\S]{0,1200}?)"
    r"(?:-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|$)"
)
_SLACK_WEBHOOK = re.compile(
    r"https?://hooks\.slack\.com/services/(?P<token>[A-Z0-9]{6,}/[A-Z0-9]{6,}/[A-Za-z0-9]{12,})",
    re.IGNORECASE,
)
_DISCORD_WEBHOOK = re.compile(
    r"https?://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/"
    r"(?P<token>\d{15,}/[A-Za-z0-9_-]{20,})",
    re.IGNORECASE,
)

_PROMPT_OVERRIDE = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override|bypass|replace)\b.{0,90}\b"
    r"(?:all\s+)?(?:previous|prior|above|system|developer|safety|guardrails?|polic(?:y|ies)|"
    r"instructions?|prompts?|rules?)\b"
)
_PROMPT_REVEAL = re.compile(
    r"(?i)\b(?:reveal|print|expose|show|dump)\b.{0,55}\b(?:system|developer)\s+"
    r"(?:prompt|instructions?|message|policy)\b"
)
_PROMPT_STEER = re.compile(
    r"(?i)\b(?:follow|obey|execute)\s+(?:this|the following)\s+(?:new\s+)?"
    r"(?:instruction|prompt|message)\s+instead\b|\bdisable\s+(?:all\s+)?(?:safety|guardrails?)\b"
)
_JAILBREAK = re.compile(r"(?i)\b(?:jailbreak|developer mode|DAN mode|do anything now)\b")
_IMPERSONATION = re.compile(
    r"(?i)\b(?:pretend to be|impersonate|act as|you are now)\b.{0,70}\b"
    r"(?:admin|administrator|system|developer|security|root|trusted user)\b"
)
_EXFIL_PROMPT = re.compile(
    r"(?i)\b(?:send|upload|exfiltrate|post|email|forward|copy|transfer)\b.{0,120}\b"
    r"(?:credentials?|secrets?|tokens?|private keys?|environment variables?|\.env|ssh keys?)\b"
)
_DESTRUCTIVE = re.compile(
    r"(?i)(?:\brm\s+-[^\n]{0,15}r[^\n]{0,15}f\s+/\S*|"
    r"\brm\s+-rf\s+(?:~|/\*|/\s|--no-preserve-root)|"
    r"\bformat(?:\.com)?\s+[a-z]:|"
    r"\bdiskpart\b[\s\S]{0,100}\bclean\b|"
    r"\bdd\s+if=[^\s]+\s+of=/dev/(?:sd[a-z]|nvme\d+n\d+)|"
    r"\bRemove-Item\b[^\n]{0,160}(?:[A-Za-z]:\\|\\\.\.\\)[^\n]{0,80}-Recurse[^\n]{0,80}-Force)"
)
_RECURSIVE_DELETE = re.compile(
    r"(?i)\b(?:Remove-Item|del|rmdir|rm)\b.{0,100}(?:-Recurse|/s\b|/q\b)"
)
_REMOTE_EXECUTION = re.compile(
    r"(?i)(?:\b(?:curl|wget)\b.{0,180}\|\s*(?:sh|bash)\b|"
    r"\b(?:iwr|irm|curl|wget)\b.{0,200}(?:downloadstring|invoke-expression|\biex\b)|"
    r"powershell\b.{0,180}(?:downloadstring|invoke-expression|\biex\b))"
)
_BASE64_EXECUTION = re.compile(
    r"(?i)(?:\bbase64\s+(?:-d|--decode)\b[^\n]{0,100}\|\s*(?:sh|bash|powershell)\b|"
    r"\bbase64\.(?:b64decode|urlsafe_b64decode)\s*\([^)]{0,180}\)"
    r"[^\n;]{0,100}\b(?:exec|eval|os\.system|subprocess\.(?:run|Popen))\s*\(|"
    r"FromBase64String\s*\([^)]{0,180}\)[^\n;]{0,100}"
    r"(?:\biex\b|Invoke-Expression|Start-Process))"
)
_CREDENTIAL_READ = re.compile(
    r"(?i)\b(?:cat|head|tail|type|more|Get-Content|gc)\s+"
    r"(?:[\"']?(?:~[/\\]\.ssh[/\\](?:id_rsa|id_ed25519)|"
    r"(?:\.env|\.aws[/\\]credentials|credentials(?:\.json)?|secrets?\.(?:json|ya?ml)|"
    r"(?:id_rsa|id_ed25519)))[\"']?)"
)
_ENVIRONMENT_ENUMERATION = re.compile(
    r"(?i)\b(?:printenv|env)\b[^\n]{0,80}"
    r"(?:\|\s*(?:grep|findstr)\b[^\n]{0,50}\b(?:key|token|secret|credential)\b|"
    r"\b(?:key|token|secret|credential)\b)"
)
_NETWORK_SECRET_SINK = re.compile(
    r"(?is)\b(?:requests|httpx|urllib|fetch|curl|Invoke-WebRequest)\b[\s\S]{0,220}"
    r"(?:\.post|\.put|upload|--data|--upload-file)[\s\S]{0,220}"
    r"(?:os\.environ|environment|credentials?|secrets?|private[_ -]?key|\.env|id_rsa)"
)
_CREDENTIAL_EXFIL = re.compile(
    r"(?is)(?:cat|head|tail|type|more|Get-Content|gc)\s+"
    r"(?:[\"']?(?:~[/\\]\.ssh[/\\](?:id_rsa|id_ed25519)|"
    r"(?:\.env|\.aws[/\\]credentials|credentials(?:\.json)?|secrets?\.(?:json|ya?ml)|"
    r"(?:id_rsa|id_ed25519)))[\"']?)[^\n]{0,240}"
    r"(?:\bcurl\b|\bwget\b|requests\.(?:post|put)|httpx\.(?:post|put)|"
    r"Invoke-WebRequest|fetch\s*\()[^\n]{0,140}"
    r"(?:https?://|--data|--upload-file|\.post|\.put)"
)
_EXPLANATORY_PREFIX = re.compile(
    r"(?i)(?:for example|e\.g\.|example:|sample:|test case|test fixture|"
    r"this (?:rule|pattern|scanner|detector)|(?:rule|pattern) (?:matches|detects|flags)|"
    r"detects? phrases? like|flagged when|should (?:be )?(?:detected|flagged)|"
    r"do not follow|never follow|not an instruction|security training)"
)
_COMMENT_MARKER = re.compile(r"^\s*(?:#|//|/\*|\*|<!--|--\s)")


@dataclass(frozen=True)
class _Indicator:
    rule_id: str
    weight: int
    confidence: int
    critical: bool = False


class RuleEngine:
    """Context-aware, confidence-weighted local indicator rules."""

    def evaluate(self, text: str, target: str, profile_id: str, custom_rules: Sequence[str] = ()) -> Finding:
        profile = SECURITY_PROFILES.get(profile_id, SECURITY_PROFILES["balanced_guard"])
        indicators = self._indicators(text, target, custom_rules)
        accepted = [
            item for item in indicators
            if item.confidence >= profile.min_confidence or (item.critical and item.confidence >= 75)
        ]
        if not accepted:
            return Finding(target, 0, "clear", [], "allow", 0)

        raw_score = sum(item.weight * item.confidence / 100 for item in accepted)
        score = min(100, round(raw_score))
        confidence = round(sum(item.weight * item.confidence for item in accepted) / sum(item.weight for item in accepted))
        critical = any(item.critical for item in accepted)
        action = (
            "quarantine" if critical or score >= profile.quarantine_score
            else "review" if score >= profile.review_score
            else "allow"
        )
        return Finding(
            target=target,
            risk_score=score,
            severity=self._severity(score),
            matched_rules=list(dict.fromkeys(item.rule_id for item in accepted)),
            recommended_action=action,
            confidence=confidence,
        )

    def _indicators(self, text: str, target: str, custom_rules: Sequence[str]) -> list[_Indicator]:
        hits: list[_Indicator] = []
        is_env_file = Path(target).name.lower() == ".env" or Path(target).name.lower().startswith(".env.")

        for pattern, rule_id, weight, confidence in (
            (_AWS_KEY, "secret_aws_key", 78, 98),
            (_PROVIDER_TOKEN, "secret_provider_token", 84, 97),
        ):
            for match in pattern.finditer(text):
                if not self._placeholder_near(text, match.start(), match.end(), match.group(0)):
                    hits.append(_Indicator(rule_id, weight, confidence, critical=True))

        for match in _ASSIGNMENT.finditer(text):
            name, value = match.group("name"), match.group("value").strip().strip("\"'")
            if self._is_placeholder(name, value) or self._explanatory(text, match.start(), match.end()):
                continue
            if len(value) < 8 or value.startswith(("$", "${", "os.getenv", "os.environ", "process.env", "env(")):
                continue
            entropy = self._entropy(value)
            if entropy < 2.2:
                continue
            confidence = 62 if len(value) < 16 else 76 if entropy < 3.2 else 88
            if is_env_file:
                confidence = min(96, confidence + 8)
            critical = confidence >= 82 and len(value) >= 16
            hits.append(_Indicator("secret_env_assignment" if is_env_file else "secret_credential_assignment", 64 if is_env_file else 58, confidence, critical))

        for match in _PRIVATE_KEY.finditer(text):
            body = match.group("body")
            if self._is_placeholder(text[match.start():match.end()], body):
                continue
            if re.search(r"[A-Za-z0-9+/]{40,}", body):
                hits.append(_Indicator("secret_private_key", 100, 99, critical=True))
            else:
                hits.append(_Indicator("secret_private_key_marker", 60, 68))

        for pattern in (_SLACK_WEBHOOK, _DISCORD_WEBHOOK):
            for match in pattern.finditer(text):
                if not self._placeholder_near(text, match.start(), match.end(), match.group("token")):
                    hits.append(_Indicator("secret_webhook_url", 82, 96, critical=True))

        for pattern, rule_id, weight, confidence in (
            (_PROMPT_OVERRIDE, "prompt_instruction_override", 42, 87),
            (_PROMPT_REVEAL, "prompt_system_prompt_theft", 40, 88),
            (_PROMPT_STEER, "prompt_safety_bypass", 40, 84),
            (_JAILBREAK, "prompt_jailbreak", 28, 79),
            (_IMPERSONATION, "prompt_impersonation", 34, 84),
            (_EXFIL_PROMPT, "prompt_secret_exfiltration", 58, 91),
        ):
            for match in pattern.finditer(text):
                if not self._explanatory(text, match.start(), match.end()):
                    hits.append(_Indicator(rule_id, weight, confidence))

        for pattern, rule_id, weight, confidence, critical in (
            (_DESTRUCTIVE, "command_destructive_system_change", 100, 99, True),
            (_RECURSIVE_DELETE, "command_recursive_delete", 58, 80, False),
            (_REMOTE_EXECUTION, "command_remote_execution_chain", 86, 93, True),
            (_BASE64_EXECUTION, "command_encoded_execution_chain", 94, 97, True),
            (_CREDENTIAL_READ, "command_credential_file_read", 34, 71, False),
            (_ENVIRONMENT_ENUMERATION, "command_environment_secret_enumeration", 26, 35, False),
            (_CREDENTIAL_EXFIL, "network_credential_exfiltration_chain", 96, 97, True),
            (_NETWORK_SECRET_SINK, "network_secret_exfiltration_sink", 82, 89, True),
        ):
            for match in pattern.finditer(text):
                if not self._explanatory(text, match.start(), match.end()):
                    hits.append(_Indicator(rule_id, weight, confidence, critical))

        folded = text.casefold()
        for raw_rule in custom_rules:
            rule = str(raw_rule).strip()
            if 2 <= len(rule) <= 120 and rule.casefold() in folded:
                hits.append(_Indicator("custom_literal_rule", 38, 78))
                break
        return hits

    @staticmethod
    def _severity(score: int) -> str:
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score > 0:
            return "low"
        return "clear"

    @staticmethod
    def _is_placeholder(name: str, value: str) -> bool:
        normalized = value.strip().strip("\"'`<>[]{}").casefold()
        if not normalized:
            return True
        if _PLACEHOLDER.search(name) or _PLACEHOLDER.search(value):
            return True
        if normalized in {"none", "null", "undefined", "todo", "tbd", "nil"}:
            return True
        if re.fullmatch(r"[x*_#-]{3,}", normalized):
            return True
        return False

    @classmethod
    def _placeholder_near(cls, text: str, start: int, end: int, value: str) -> bool:
        context = text[max(0, start - 100):min(len(text), end + 100)]
        return cls._is_placeholder("", value) or bool(_PLACEHOLDER.search(context))

    @staticmethod
    def _explanatory(text: str, start: int, end: int) -> bool:
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", end)
        if line_end < 0:
            line_end = len(text)
        line = text[line_start:line_end]
        prefix = text[max(0, start - 120):start]
        return bool(_COMMENT_MARKER.search(line) or _EXPLANATORY_PREFIX.search(prefix))

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())


class Scanner:
    """Heuristic scanner; findings are indicators and do not prove compromise."""

    def __init__(self, custom_rules: Sequence[str] | None = None) -> None:
        self.rule_engine = RuleEngine()
        self.custom_rules = tuple(custom_rules or ())

    def scan_text(self, text: str, target: str = "pasted text", profile: str = "balanced_guard") -> Finding:
        return self.rule_engine.evaluate(text, target, profile, self.custom_rules)

    def scan_path(self, target: Path | str, profile: str = "balanced_guard") -> list[Finding]:
        path = Path(target).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        if path.is_file():
            return [self._scan_file(path, profile)]
        if not path.is_dir():
            raise ValueError(f"Unsupported scan target: {path}")
        return [self._scan_file(file_path, profile) for file_path in self._iter_files(path)]

    def _scan_file(self, path: Path, profile: str) -> Finding:
        try:
            size = path.stat().st_size
            with path.open("rb") as source:
                raw = source.read(_MAX_FILE_BYTES + 1)
            content = raw[:_MAX_FILE_BYTES].decode("utf-8", errors="ignore")
        except OSError as exc:
            raise OSError(f"Unable to read scan target {path}: {exc}") from exc

        finding = self.scan_text(content, str(path), profile)
        rules = list(finding.matched_rules)
        score = finding.risk_score
        confidence = finding.confidence
        if len(path.suffixes) > 1 and path.suffixes[-1].lower() in {".exe", ".scr", ".bat", ".cmd"}:
            rules.append("file_double_extension")
            score = min(100, score + 30)
            confidence = max(confidence, 76)
        if size > _MAX_FILE_BYTES:
            rules.append("file_scan_truncated")
            confidence = min(confidence, 55)
            score = min(score, 35)
        selected_profile = SECURITY_PROFILES.get(profile, SECURITY_PROFILES["balanced_guard"])
        action = (
            "quarantine" if score >= selected_profile.quarantine_score
            else "review" if score >= selected_profile.review_score
            else "allow"
        )
        return Finding(str(path), score, self._severity(score), rules, action, confidence)

    @staticmethod
    def _iter_files(root: Path) -> Iterable[Path]:
        for current, dirs, files in os.walk(root):
            dirs[:] = [name for name in dirs if name not in {".git", "__pycache__", "quarantine"}]
            for name in files:
                candidate = Path(current) / name
                if not candidate.is_symlink():
                    yield candidate

    @staticmethod
    def _severity(score: int) -> str:
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score > 0:
            return "low"
        return "clear"

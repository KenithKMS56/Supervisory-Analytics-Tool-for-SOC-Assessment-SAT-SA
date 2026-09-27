"""Regex-based PII/identifier redaction, normalization hashing, and text shingling."""

import hashlib
import re

IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
HOSTNAME_REGEX = re.compile(
    r"\b[a-zA-Z0-9][-a-zA-Z0-9]{1,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{1,62})+\b"
)
LONG_DIGITS_REGEX = re.compile(r"\b\d{8,}\b")


class Redactor:
    """Redacts sensitive identifiers, computes normalized hashes, and generates k-shingles."""

    @staticmethod
    def redact_text(text: str) -> str:
        """Redact IPs, emails, hostnames, and long digit strings from free text."""
        if not text:
            return ""
        s = EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
        s = IPV4_REGEX.sub("[REDACTED_IPV4]", s)
        s = IPV6_REGEX.sub("[REDACTED_IPV6]", s)
        s = HOSTNAME_REGEX.sub("[REDACTED_HOST]", s)
        s = LONG_DIGITS_REGEX.sub("[REDACTED_NUM]", s)
        return s

    @staticmethod
    def compute_norm_hash(text: str) -> str:
        """Normalized text hash: lowercased, whitespace-collapsed SHA-256."""
        if not text:
            return hashlib.sha256(b"").hexdigest()[:16]
        norm = " ".join(text.lower().strip().split())
        return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def generate_shingles(text: str, k: int = 3) -> list[str]:
        """Generate word-level k-shingles for Jaccard similarity estimation."""
        if not text:
            return []
        words = [w for w in re.split(r"\W+", text.lower()) if len(w) > 2]
        if len(words) < k:
            return ["_".join(words)] if words else []
        return ["_".join(words[i : i + k]) for i in range(len(words) - k + 1)]

    @staticmethod
    def jaccard_similarity(shingles_a: list[str], shingles_b: list[str]) -> float:
        """Calculate exact Jaccard similarity between two sets of shingles."""
        set_a = set(shingles_a)
        set_b = set(shingles_b)
        if not set_a and not set_b:
            return 1.0
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        return intersection / union

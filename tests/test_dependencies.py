"""No cloud, SaaS, telemetry or hosted-AI client among the locked dependencies (PS D3-D5).

Reads every package in `uv.lock` (runtime and development) and checks the names against the
client libraries of cloud platforms, SaaS telemetry and hosted or local AI/ML stacks. A name
list cannot prove the absence of every possible client; together with the egress guard and the
offline tests (`tests/test_offline.py`) it keeps one from being added unnoticed.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

FORBIDDEN = re.compile(
    r"^("
    r"boto3|botocore|aiobotocore|s3fs|google-cloud-.*|google-api-.*|google-auth|azure-.*|gcsfs|adlfs"  # cloud
    r"|sentry-sdk|datadog|ddtrace|newrelic|mixpanel|segment-analytics-python|posthog|opentelemetry-exporter-.*"  # telemetry
    r"|openai|anthropic|cohere|mistralai|google-generativeai|google-genai|langchain.*|llama-index.*|litellm"  # hosted AI
    r"|transformers|torch|tensorflow|keras|jax|sentence-transformers|huggingface-hub|scikit-learn|xgboost|lightgbm"  # ML
    r")$"
)


def _locked() -> list[str]:
    with open(REPO / "uv.lock", "rb") as fh:
        return sorted(p["name"] for p in tomllib.load(fh)["package"])


def test_no_cloud_saas_telemetry_or_ai_package_is_locked():
    names = _locked()
    assert len(names) > 20  # the lock file was read
    assert [n for n in names if FORBIDDEN.match(n)] == []


def test_the_check_recognises_the_packages_it_forbids():
    for name in ("boto3", "google-cloud-storage", "azure-identity", "sentry-sdk", "openai", "anthropic", "torch",
                 "langchain-core", "scikit-learn"):  # fmt: skip
        assert FORBIDDEN.match(name), name
    for name in ("duckdb", "polars", "fastapi", "cryptography", "httpx"):
        assert not FORBIDDEN.match(name), name

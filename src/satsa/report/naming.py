"""Short, readable file names for generated PDF reports.

Report files are written under the working directory (`reports/`), and on Windows a full path
longer than 260 characters cannot be created. The old names carried the whole run ID (and,
for a finding, the whole finding ID, which itself contains the run ID): about 75 characters
before the directory. These names keep what a reader needs -- what the report is, which
entity, which rule, the run date -- and identify the run by its date and random suffix.

  portfolio  SATSA_Portfolio_20261001-ea12a0fc.pdf
  entity     SATSA_CSE-03_20261001-ea12a0fc.pdf
  finding    SATSA_Finding_EG10_CSE-02_3f9a1c2b.pdf   (8-hex hash of the finding ID)
"""

from __future__ import annotations

import hashlib
import re

# RUN-<20-digit timestamp>-<8 hex>, e.g. RUN-20261001092757137058-ea12a0fc (scoring/runner.py)
_RUN_ID = re.compile(r"^RUN-(\d{8})\d*-([0-9A-Za-z]+)$")


def _digest(text: str, length: int = 8) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def short_run_label(run_id: str) -> str:
    """`RUN-20261001092757137058-ea12a0fc` -> `20261001-ea12a0fc`; any other ID -> a 12-hex hash."""
    match = _RUN_ID.match(run_id)
    if match:
        return f"{match.group(1)}-{match.group(2)[:8]}"
    return _digest(run_id, 12)


def portfolio_pdf_name(run_id: str) -> str:
    return f"SATSA_Portfolio_{short_run_label(run_id)}.pdf"


def entity_pdf_name(entity_id: str, run_id: str) -> str:
    return f"SATSA_{entity_id}_{short_run_label(run_id)}.pdf"


def finding_pdf_name(finding_id: str, rule_id: str, entity_id: str) -> str:
    return f"SATSA_Finding_{rule_id}_{entity_id}_{_digest(finding_id)}.pdf"

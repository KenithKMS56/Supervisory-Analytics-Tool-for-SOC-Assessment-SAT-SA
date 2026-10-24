"""Offline explanation requests and responses (docs/examiner_workflow.md, "Response packages").

SAT-SA has no portal for regulated entities in v1. An examiner exports a *request package* (a
zip) for a case awaiting an explanation and sends it by whatever channel the regulator uses.
The entity answers with a *response package*, which the case owner imports.

The request package carries only what the entity needs to answer: the case reference, the
concern's title, the examiner's request and the date it is due. It never contains scores,
severities, peer comparisons, other entities or evidence records.

Each request carries a token, an HMAC-SHA256 of the package's identity under a key kept in
`data/secrets/case_package_key`. A response is accepted only if it echoes that token, answers
the case's current request, and arrives while the case still awaits it. Importing the same
response again changes nothing; a different response to an answered request is refused.

A response package is untrusted input: it is checked against size, member-count and
compression limits and member names before anything is read, and its files are stored as
evidence attachments (content-addressed, never executed or served inline).
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import secrets
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from satsa.admin.rbac import is_examiner
from satsa.cases import workflow
from satsa.cases.workflow import (
    Attachment,
    CaseError,
    CaseForbidden,
    CaseInvalid,
    InvalidTransition,
)
from satsa.keys import secrets_dir, write_private
from satsa.security import safe_archive_member
from satsa.store.sqlite import SQLiteStore, utc_now_iso

REQUEST_FORMAT = "satsa-case-request/1"
RESPONSE_FORMAT = "satsa-case-response/1"
KEY_FILE = "case_package_key"
MAX_PACKAGE_BYTES = 50 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_MEMBERS = 51  # response.json and up to 50 attachments
MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024
MAX_RESPONSE_JSON_BYTES = 1024 * 1024
MAX_RATIO = 100
ZIP_TIME = (2026, 1, 1, 0, 0, 0)

README = """SAT-SA explanation request
==========================

This package is a request from your supervisory examiner. request.json says what is asked
and by when.

To answer:
1. Copy response_template.json to a file named response.json.
2. Fill in responder_name, responder_role and explanation. Leave package_id, case_id and
   token exactly as they are: they tie your answer to this request.
3. Put any supporting documents in a folder named attachments/ and list their file names
   in "attachments".
4. Zip response.json and the attachments/ folder together (response.json at the top of the
   zip) and return the zip to your examiner.

Limits: at most 50 attachments, each up to 20 MiB, 50 MiB for the whole zip.
"""


class PackageConflict(CaseError):
    status = 409


def _key(data_dir: Path | str) -> bytes:
    path = secrets_dir(data_dir) / KEY_FILE
    if not path.exists():
        write_private(path, secrets.token_hex(32).encode())
    return bytes.fromhex(path.read_text(encoding="ascii").strip())


def _token(data_dir: Path | str, package_id: str, case_id: str, request_event_id: str) -> str:
    message = f"{REQUEST_FORMAT}\x1f{package_id}\x1f{case_id}\x1f{request_event_id}".encode()
    return hmac.new(_key(data_dir), message, hashlib.sha256).hexdigest()


def _latest_request(store: SQLiteStore, case_id: str) -> dict[str, Any] | None:
    reqs = [e for e in workflow.events(store, case_id) if e["action"] == "request_explanation"]
    return reqs[-1] if reqs else None


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in members.items():
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, content)
    return buf.getvalue()


def export_request(store: SQLiteStore, case_id: str, actor: str, role: str,
                   data_dir: Path | str = "data", deployment_name: str = "") -> tuple[str, bytes]:
    """The request package of the case's current explanation request: (file name, zip bytes)."""
    if not is_examiner(role):
        raise CaseForbidden("Only examiners export explanation requests.")
    with store.audited_transaction():
        case = workflow.get_case(store, case_id)
        if case["owner"] != actor:
            raise CaseForbidden(f"Only the case owner ({case['owner']}) exports its requests.")
        if case["state"] != "explanation_requested":
            raise InvalidTransition("The case is not awaiting an explanation.")
        request = _latest_request(store, case_id)
        if request is None:  # cannot happen in this state; kept as a guard
            raise InvalidTransition("The case has no explanation request.")
        row = store.conn.execute(
            "SELECT package_id FROM case_packages WHERE request_event_id = ?", (request["event_id"],)
        ).fetchone()
        if row is None:
            package_id = f"PKG-{secrets.token_hex(6).upper()}"
            store.conn.execute(
                "INSERT INTO case_packages (package_id, case_id, request_event_id, exported_by, exported_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (package_id, case_id, request["event_id"], actor, utc_now_iso()),
            )
        else:
            package_id = row["package_id"]
        store.append_audit("case_request_exported", actor, {"case_id": case_id, "package_id": package_id})
    token = _token(data_dir, package_id, case_id, request["event_id"])
    req = {
        "format": REQUEST_FORMAT,
        "package_id": package_id,
        "case_id": case_id,
        "entity_id": case["entity_id"],
        "issued_by": deployment_name or "SAT-SA supervisory deployment",
        "concern": {"rule_id": case["rule_id"], "title": case["title"]},
        "request": request["rationale"],
        "requested_at": request["created_at"],
        "respond_by": request["payload"].get("respond_by"),
        "token": token,
    }
    template = {
        "format": RESPONSE_FORMAT,
        "package_id": package_id,
        "case_id": case_id,
        "token": token,
        "responder_name": "",
        "responder_role": "",
        "explanation": "",
        "attachments": [],
    }
    content = _zip({
        "request.json": json.dumps(req, indent=2).encode(),
        "response_template.json": json.dumps(template, indent=2).encode(),
        "README.txt": README.encode(),
    })
    return f"{case_id}-{package_id}-request.zip", content


def _read_member(z: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    """Read at most `limit` bytes, whatever the member's header claims."""
    with z.open(info) as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise CaseInvalid(f"{info.filename!r} is larger than {limit // (1024 * 1024)} MiB.")
    return data


def _parse_package(content: bytes) -> tuple[dict[str, Any], list[Attachment]]:
    if len(content) > MAX_PACKAGE_BYTES:
        raise CaseInvalid(f"The response package is larger than {MAX_PACKAGE_BYTES // (1024 * 1024)} MiB.")
    try:
        z = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise CaseInvalid("The response package is not a zip file.") from exc
    with z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        if len(infos) > MAX_MEMBERS:
            raise CaseInvalid(f"The response package has more than {MAX_MEMBERS} files.")
        total = 0
        response_info = None
        files: list[zipfile.ZipInfo] = []
        for info in infos:
            try:
                path = safe_archive_member(info.filename)
            except ValueError as exc:
                raise CaseInvalid(str(exc)) from exc
            total += info.file_size
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO and info.file_size > 1024 * 1024:
                raise CaseInvalid(f"{info.filename!r} expands more than {MAX_RATIO}x; refused.")
            if path == PurePosixPath("response.json"):
                response_info = info
            elif len(path.parts) == 2 and path.parts[0] == "attachments":
                files.append(info)
            else:
                raise CaseInvalid(f"Unexpected file {info.filename!r}: only response.json and attachments/ are read.")
        if total > MAX_UNCOMPRESSED_BYTES:
            raise CaseInvalid("The response package expands beyond the size limit.")
        if response_info is None:
            raise CaseInvalid("The response package has no response.json.")
        try:
            response = json.loads(_read_member(z, response_info, MAX_RESPONSE_JSON_BYTES).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CaseInvalid("response.json is not valid JSON.") from exc
        if not isinstance(response, dict) or response.get("format") != RESPONSE_FORMAT:
            raise CaseInvalid(f"response.json is not a {RESPONSE_FORMAT} document.")
        atts = [Attachment(PurePosixPath(i.filename).name, _read_member(z, i, MAX_ATTACHMENT_BYTES),
                           source="response_package") for i in files]
    listed = response.get("attachments") or []
    if not isinstance(listed, list) or not all(isinstance(n, str) for n in listed):
        raise CaseInvalid("'attachments' in response.json must be a list of file names.")
    present = {a.filename for a in atts}
    if listed and set(listed) != present:
        missing, extra = sorted(set(listed) - present), sorted(present - set(listed))
        raise CaseInvalid(f"Attachments do not match response.json (missing {missing}, not listed {extra}).")
    return response, atts


def import_response(store: SQLiteStore, case_id: str, content: bytes, actor: str, role: str,
                    expected_version: int, data_dir: Path | str = "data") -> dict[str, Any]:
    """Record an entity's response package on its case. Returns {event_id, duplicate}."""
    response, atts = _parse_package(content)
    package_id = str(response.get("package_id", ""))
    sha = hashlib.sha256(content).hexdigest()
    for key in ("responder_name", "explanation"):
        if not str(response.get(key, "")).strip():
            raise CaseInvalid(f"response.json has no {key}.")
    with store.audited_transaction():
        pkg = store.conn.execute(
            "SELECT * FROM case_packages WHERE package_id = ? AND case_id = ?", (package_id, case_id)
        ).fetchone()
        if pkg is None or str(response.get("case_id")) != case_id:
            raise CaseInvalid("This response does not answer a request exported for this case.")
        expected = _token(data_dir, package_id, case_id, pkg["request_event_id"])
        if not hmac.compare_digest(expected, str(response.get("token", ""))):
            raise CaseInvalid("The response's token does not match the request: it was altered or is not ours.")
        if pkg["response_sha256"]:
            if pkg["response_sha256"] == sha:
                return {"event_id": pkg["response_event_id"], "duplicate": True, "package_id": package_id}
            raise PackageConflict("A different response to this request was already imported. "
                                  "Request a new explanation if the entity sent a revised answer.")
        latest = _latest_request(store, case_id)
        if latest is None or latest["event_id"] != pkg["request_event_id"]:
            raise InvalidTransition("This request was superseded by a later one; the response answers an old request.")
        event = workflow.apply(
            store, case_id, "record_response", actor, role, expected_version,
            rationale=str(response["explanation"]), files=atts, data_dir=data_dir,
            payload_extra={
                "package_id": package_id,
                "response_sha256": sha,
                "responder_name": str(response["responder_name"])[:200],
                "responder_role": str(response.get("responder_role", ""))[:200],
            },
        )
        store.conn.execute(
            "UPDATE case_packages SET response_sha256 = ?, response_event_id = ?, imported_by = ?, imported_at = ? "
            "WHERE package_id = ?",
            (sha, event["event_id"], actor, utc_now_iso(), package_id),
        )
        return {"event_id": event["event_id"], "duplicate": False, "package_id": package_id}


def packages(store: SQLiteStore, case_id: str) -> list[dict[str, Any]]:
    return [dict(r) for r in store.conn.execute(
        "SELECT * FROM case_packages WHERE case_id = ? ORDER BY exported_at", (case_id,))]

"""Offline explanation requests and responses (satsa.cases.packages).

The request carries nothing supervisor-only; a response must answer this deployment's current
request for the case, unaltered; a package is untrusted input and is refused, before anything
is recorded, when it is malformed, oversized or tries to escape its directory.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from case_fixtures import make_store
from test_cases import EX, EX2, act, opened_and_assigned, response_zip

from satsa.cases import packages, workflow
from satsa.cases.packages import PackageConflict
from satsa.cases.workflow import CaseForbidden, CaseInvalid, InvalidTransition


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = make_store(tmp_path)
    yield s
    s.close()


@pytest.fixture
def requested(store):
    case_id = opened_and_assigned(store)
    act(store, case_id, "request_explanation", rationale="Explain the off-shift delays in Q1.", due_date="2026-05-15")
    _name, request = packages.export_request(store, case_id, EX, "examiner", deployment_name="Test regulator")
    return case_id, request


def _import(store, case_id, content, actor=EX):
    version = workflow.get_case(store, case_id)["version"]
    return packages.import_response(store, case_id, content, actor, "examiner", version)


def _events(store, case_id):
    return [e["action"] for e in workflow.events(store, case_id)]


def test_the_request_package_carries_only_what_the_entity_needs(store, requested):
    case_id, request = requested
    with zipfile.ZipFile(io.BytesIO(request)) as z:
        assert sorted(z.namelist()) == ["README.txt", "request.json", "response_template.json"]
        req = json.loads(z.read("request.json"))
        raw = b"".join(z.read(n) for n in z.namelist()).decode().lower()
    assert req["case_id"] == case_id and req["respond_by"] == "2026-05-15"
    assert req["request"] == "Explain the off-shift delays in Q1." and len(req["token"]) == 64
    assert req["issued_by"] == "Test regulator"
    # Nothing supervisor-only: no score, severity, peers, index, evidence records or other entities.
    for word in ("score", "severity", "peer", "risk_index", "a-1", "confidence", "cse-02"):
        assert word not in raw, word
    # Exporting again gives the same package for the same request.
    _n, again = packages.export_request(store, case_id, EX, "examiner", deployment_name="Test regulator")
    assert again == request and len(packages.packages(store, case_id)) == 1
    with pytest.raises(CaseForbidden):
        packages.export_request(store, case_id, EX2, "examiner")


def test_a_response_is_recorded_once_and_a_different_one_is_refused(store, requested):
    case_id, request = requested
    content = response_zip(request, attachments={"rota.pdf": b"%PDF rota", "log.csv": b"t,n\n"})
    first = _import(store, case_id, content)
    assert not first["duplicate"]
    case = workflow.get_case(store, case_id)
    assert case["state"] == "response_received"
    event = workflow.events(store, case_id)[-1]
    assert event["payload"]["responder_name"] == "R. Iyer" and event["rationale"].startswith("Night shift")
    assert sorted(a["filename"] for a in workflow.attachments(store, case_id)) == ["log.csv", "rota.pdf"]

    again = packages.import_response(store, case_id, content, EX, "examiner", 1)  # stale version is moot
    assert again == {**first, "duplicate": True}
    assert _events(store, case_id).count("record_response") == 1
    with pytest.raises(PackageConflict):
        _import(store, case_id, response_zip(request, explanation="A different story."))


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (lambda r: r.update(token="0" * 64), "token does not match"),
        (lambda r: r.update(case_id="CASE-FFFFFFFFFFFF"), "does not answer a request"),
        (lambda r: r.update(package_id="PKG-000000000000"), "does not answer a request"),
        (lambda r: r.update(format="something-else"), "not a satsa-case-response/1"),
        (lambda r: r.update(explanation=""), "no explanation"),
        (lambda r: r.update(attachments=["missing.pdf"]), "do not match"),
    ],
)
def test_altered_or_foreign_responses_are_refused(store, requested, mutate, error):
    case_id, request = requested
    with zipfile.ZipFile(io.BytesIO(request)) as z:
        doc = json.loads(z.read("response_template.json"))
    doc.update(responder_name="R. Iyer", explanation="Because.")
    mutate(doc)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        out.writestr("response.json", json.dumps(doc))
    with pytest.raises(CaseInvalid, match=error):
        _import(store, case_id, buf.getvalue())
    assert workflow.get_case(store, case_id)["state"] == "explanation_requested"


def _zip(members: dict[str, bytes], compression=zipfile.ZIP_STORED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as out:
        for name, data in members.items():
            out.writestr(name, data)
    return buf.getvalue()


@pytest.mark.parametrize(
    ("members", "error"),
    [
        ({"response.json": b"{}", "../escape.txt": b"x"}, "Unsafe archive member"),
        ({"response.json": b"{}", "attachments/../../x": b"x"}, "Unsafe archive member"),
        ({"response.json": b"{}", "notes.txt": b"x"}, "Unexpected file"),
        ({"response.json": b"{}", "attachments/sub/deep.txt": b"x"}, "Unexpected file"),
        ({"attachments/a.txt": b"x"}, "no response.json"),
        ({"response.json": b"not json"}, "not valid JSON"),
    ],
)
def test_malformed_packages_are_refused(store, requested, members, error):
    case_id, _request = requested
    with pytest.raises(CaseInvalid, match=error):
        _import(store, case_id, _zip(members))


def test_oversized_and_bomb_packages_are_refused(store, requested, monkeypatch):
    case_id, request = requested
    with pytest.raises(CaseInvalid, match="not a zip"):
        _import(store, case_id, b"this is not a zip")
    monkeypatch.setattr(packages, "MAX_ATTACHMENT_BYTES", 1024)
    with pytest.raises(CaseInvalid, match="larger than"):
        _import(store, case_id, response_zip(request, attachments={"big.bin": b"x" * 4096}))
    bomb = response_zip(request)  # a valid response, plus a member that inflates enormously
    with zipfile.ZipFile(io.BytesIO(bomb)) as z:
        members = {n: z.read(n) for n in z.namelist()}
    members["attachments/zeros.bin"] = b"\0" * (8 * 1024 * 1024)
    with pytest.raises(CaseInvalid, match="expands more than"):
        _import(store, case_id, _zip(members, zipfile.ZIP_DEFLATED))
    monkeypatch.setattr(packages, "MAX_PACKAGE_BYTES", 100)
    with pytest.raises(CaseInvalid, match="larger than"):
        _import(store, case_id, response_zip(request))
    assert workflow.attachments(store, case_id) == []


def test_a_response_to_a_superseded_request_is_refused(store, requested):
    case_id, old_request = requested
    act(store, case_id, "record_response", rationale="Answered by phone; summary attached later.")
    act(store, case_id, "request_explanation", rationale="Send the Q1 rota.", due_date="2026-06-01")
    with pytest.raises(InvalidTransition, match="superseded"):
        _import(store, case_id, response_zip(old_request))
    _n, new_request = packages.export_request(store, case_id, EX, "examiner")
    assert _import(store, case_id, response_zip(new_request))["duplicate"] is False


def test_only_the_owner_imports_and_only_while_a_response_is_awaited(store, requested):
    case_id, request = requested
    with pytest.raises(CaseForbidden):
        _import(store, case_id, response_zip(request), actor=EX2)
    act(store, case_id, "decide", outcome="inconclusive", rationale="No answer in time.")
    with pytest.raises(InvalidTransition):
        _import(store, case_id, response_zip(request))

"""Phase 9: bounded, evidence-aware operational audit reporting.

A report is built from database aggregates only. No tool arguments, tool
descriptions, credentials, OAuth data, policies, arbitrary audit JSON, source
paths, untrusted finding descriptions, or cloud resource ARNs are exported.
No mapping, risk recalculation, network calls, scans, AI calls, or mutations.
"""
from __future__ import annotations

import csv
from datetime import datetime, timedelta
import hashlib
import html
import io
import json
import re
import textwrap
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.build_security import BuildAssessment, BuildFinding, BuildScanRun
from app.models.cloud_security import CloudFinding, CloudIAMComparison, CloudScan
from app.models.control_plane import (
    ControlPlaneAuditEvent, ControlPlaneConfigRevision, EmergencyDeny,
)
from app.models.mcp_server import MCPServer
from app.models.mcp_tool import MCPTool
from app.models.runtime_call import RuntimeCall
from app.models.tool_analysis import ToolAnalysis, ToolAnalysisFinding
from app.services.runtime_outcome_taxonomy import runtime_outcome_bucket_expression

PERIOD_DAYS = {"7d": 7, "30d": 30, "90d": 90, "all": None}
FORMAT_TYPES = {
    "pdf": ("application/pdf", "pdf"),
    "html": ("text/html; charset=utf-8", "html"),
    "json": ("application/json; charset=utf-8", "json"),
    "csv": ("text/csv; charset=utf-8", "csv"),
}
MAX_EVIDENCE_PER_SECTION = 12
SAFE_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _safe_category(value: Any) -> str:
    """Keep only bounded, display-safe status codes from DB-controlled fields."""
    code = str(value or "UNKNOWN").upper().strip()
    return code if SAFE_CODE.fullmatch(code) else "OTHER"


def _counts(
    db: Session,
    model: type,
    column: Any,
    *,
    date_column: Any | None = None,
    since: datetime | None = None,
    until: datetime,
    join_model: Any | None = None,
) -> dict[str, int]:
    stmt = select(column, func.count()).select_from(model)
    if join_model is not None:
        stmt = stmt.join(join_model)
    if date_column is not None:
        stmt = stmt.where(date_column <= until)
        if since is not None:
            stmt = stmt.where(date_column >= since)
    stmt = stmt.group_by(column)
    result: dict[str, int] = {}
    for value, amount in db.execute(stmt):
        key = _safe_category(value)
        result[key] = result.get(key, 0) + int(amount)
    return dict(sorted(result.items(), key=lambda x: (-x[1], x[0])))


def _total(
    db: Session,
    model: type,
    *,
    date_column: Any | None = None,
    since: datetime | None = None,
    until: datetime,
    join_model: Any | None = None,
) -> int:
    stmt = select(func.count()).select_from(model)
    if join_model is not None:
        stmt = stmt.join(join_model)
    if date_column is not None:
        stmt = stmt.where(date_column <= until)
        if since is not None:
            stmt = stmt.where(date_column >= since)
    return int(db.scalar(stmt) or 0)


def _evidence(
    db: Session,
    model: type,
    id_col: Any,
    date_col: Any,
    *,
    since: datetime | None,
    until: datetime,
    status_col: Any,
) -> list[dict[str, str]]:
    query = select(id_col, date_col, status_col).select_from(model).where(date_col <= until)
    if since is not None:
        query = query.where(date_col >= since)
    records = db.execute(query.order_by(date_col.desc(), id_col.desc()).limit(MAX_EVIDENCE_PER_SECTION))
    return [
        {
            # Exact internal primary keys remain traceable to the audit console.
            # Non-standard identifiers are hashed rather than exporting content.
            "reference": (
                str(identifier) if re.fullmatch(r"(?:[0-9]{1,14}|[0-9a-fA-F-]{36})", str(identifier))
                else hashlib.sha256(str(identifier).encode("utf-8")).hexdigest()[:16]
            ),
            "time_utc": stamp.isoformat() if stamp is not None else "UNKNOWN",
            "status": _safe_category(status),
        }
        for identifier, stamp, status in records
    ]


def collect_report(
    db: Session,
    *,
    period: str,
    include_evidence: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    if period not in PERIOD_DAYS:
        raise ValueError("unsupported_report_period")
    now = now or datetime.utcnow()
    if now.tzinfo is not None:
        raise ValueError("report_timestamp_must_be_naive_utc")
    days = PERIOD_DAYS[period]
    since = now - timedelta(days=days) if days is not None else None
    evidence: dict[str, list[dict[str, str]]] = {}

    inventory = {
        "servers": _total(db, MCPServer, until=now),
        "server_trust": _counts(db, MCPServer, MCPServer.trust_status, until=now),
        "tools": _total(db, MCPTool, until=now),
        "tool_analysis_status": _counts(db, MCPTool, MCPTool.analysis_status, until=now),
        "tool_risk": _counts(db, MCPTool, MCPTool.risk_level, until=now),
        "tool_reviews": _counts(db, MCPTool, MCPTool.review_status, until=now),
    }
    tool_analysis = {
        "analyses": _total(db, ToolAnalysis, date_column=ToolAnalysis.created_at, since=since, until=now),
        "status": _counts(db, ToolAnalysis, ToolAnalysis.analysis_status,
                          date_column=ToolAnalysis.created_at, since=since, until=now),
        "drift": _counts(db, ToolAnalysis, ToolAnalysis.drift_status,
                         date_column=ToolAnalysis.created_at, since=since, until=now),
        "findings": _total(db, ToolAnalysisFinding, date_column=ToolAnalysisFinding.created_at,
                           since=since, until=now),
        "severity": _counts(db, ToolAnalysisFinding, ToolAnalysisFinding.severity,
                            date_column=ToolAnalysisFinding.created_at, since=since, until=now),
    }
    build = {
        "scans": _total(db, BuildScanRun, date_column=BuildScanRun.created_at, since=since, until=now),
        "scan_status": _counts(db, BuildScanRun, BuildScanRun.status,
                               date_column=BuildScanRun.created_at, since=since, until=now),
        "findings": _total(db, BuildFinding, date_column=BuildFinding.created_at, since=since, until=now),
        "severity": _counts(db, BuildFinding, BuildFinding.severity,
                            date_column=BuildFinding.created_at, since=since, until=now),
        "assessments": _counts(db, BuildAssessment, BuildAssessment.status,
                               date_column=BuildAssessment.created_at, since=since, until=now),
    }
    cloud = {
        "scans": _total(db, CloudScan, date_column=CloudScan.created_at, since=since, until=now),
        "scan_status": _counts(db, CloudScan, CloudScan.status,
                               date_column=CloudScan.created_at, since=since, until=now),
        "scan_kind": _counts(db, CloudScan, CloudScan.kind,
                             date_column=CloudScan.created_at, since=since, until=now),
        # CloudFinding and CloudIAMComparison have no independent timestamp:
        # constrain them by the linked scan's created_at, never claim otherwise.
        "findings": _total(db, CloudFinding, date_column=CloudScan.created_at,
                           since=since, until=now, join_model=CloudScan),
        "severity": _counts(db, CloudFinding, CloudFinding.severity,
                            date_column=CloudScan.created_at, since=since,
                            until=now, join_model=CloudScan),
        "iam_comparisons": _counts(db, CloudIAMComparison, CloudIAMComparison.status,
                                   date_column=CloudScan.created_at, since=since,
                                   until=now, join_model=CloudScan),
    }
    runtime_bucket = runtime_outcome_bucket_expression()
    runtime = {
        "events": _total(db, RuntimeCall, date_column=RuntimeCall.created_at, since=since, until=now),
        "outcomes": _counts(db, RuntimeCall, runtime_bucket, date_column=RuntimeCall.created_at,
                            since=since, until=now),
        "decisions": _counts(db, RuntimeCall, RuntimeCall.decision,
                             date_column=RuntimeCall.created_at, since=since, until=now),
        "opa_decisions": _counts(db, RuntimeCall, RuntimeCall.opa_decision,
                                 date_column=RuntimeCall.created_at, since=since, until=now),
    }
    audit = {
        "events": _total(db, ControlPlaneAuditEvent,
                          date_column=ControlPlaneAuditEvent.timestamp, since=since, until=now),
        "results": _counts(db, ControlPlaneAuditEvent, ControlPlaneAuditEvent.result,
                           date_column=ControlPlaneAuditEvent.timestamp, since=since, until=now),
        "actions": _counts(db, ControlPlaneAuditEvent, ControlPlaneAuditEvent.action,
                           date_column=ControlPlaneAuditEvent.timestamp, since=since, until=now),
    }
    active_emergency = int(db.scalar(select(func.count()).select_from(EmergencyDeny).where(
        EmergencyDeny.created_at <= now,
        EmergencyDeny.expires_at > now,
        EmergencyDeny.revoked_at.is_(None),
    )) or 0)
    rev = db.execute(
        select(ControlPlaneConfigRevision.revision_number, ControlPlaneConfigRevision.content_hash)
        .where(ControlPlaneConfigRevision.status == "PUBLISHED",
               ControlPlaneConfigRevision.published_at <= now)
        .order_by(ControlPlaneConfigRevision.published_at.desc()).limit(1)
    ).first()
    governance = {
        "active_emergency_restrictions": active_emergency,
        "published_revision_number": int(rev[0]) if rev is not None else None,
        "published_revision_sha256": rev[1] if rev is not None else None,
    }
    if include_evidence:
        evidence = {
            "runtime": _evidence(db, RuntimeCall, RuntimeCall.id, RuntimeCall.created_at,
                                 since=since, until=now, status_col=RuntimeCall.execution_status),
            "build_scans": _evidence(db, BuildScanRun, BuildScanRun.id, BuildScanRun.created_at,
                                      since=since, until=now, status_col=BuildScanRun.status),
            "cloud_scans": _evidence(db, CloudScan, CloudScan.id, CloudScan.created_at,
                                      since=since, until=now, status_col=CloudScan.status),
            "audit": _evidence(db, ControlPlaneAuditEvent, ControlPlaneAuditEvent.id,
                                ControlPlaneAuditEvent.timestamp, since=since, until=now,
                                status_col=ControlPlaneAuditEvent.result),
        }

    notes = [
        "Inventory totals are current recorded state, not historic inventory as of the period start.",
        "Cloud findings and IAM comparisons use their linked scan creation date.",
        "Runtime events are outcome rows; they must not be treated as unique or confirmed tool executions.",
        "No record or alert is not proof of safety or verification; scanner coverage and missing evidence require separate review.",
        "Reports are summaries of recorded evidence, not certifications, regulatory mappings, or live scans.",
        "No untrusted tool content, raw requests, secrets, policies, tokens, paths, or external cloud resource identifiers are included.",
    ]
    recommendations = []
    if tool_analysis["severity"].get("CRITICAL", 0) or build["severity"].get("CRITICAL", 0) or cloud["severity"].get("CRITICAL", 0):
        recommendations.append("Review recorded critical findings using their original evidence in the security console.")
    if runtime["outcomes"].get("SENT_UNCERTAIN", 0):
        recommendations.append("Investigate upstream-uncertain Runtime outcomes; they are not confirmed denials.")
    if cloud["scan_status"].get("FAILED", 0) or build["scan_status"].get("FAILED", 0):
        recommendations.append("Review failed scanner runs and coverage before drawing conclusions.")
    if not recommendations:
        recommendations.append("Review underlying findings and coverage; lack of alerts is not proof of safety.")

    return {
        "schema_version": "phase9-audit-report-v1",
        "report_id": str(uuid4()),
        "generated_at_utc": now.isoformat(),
        "period": period,
        "since_utc": since.isoformat() if since else None,
        "until_utc": now.isoformat(),
        "inventory": inventory,
        "tool_security": tool_analysis,
        "build_security": build,
        "cloud_security": cloud,
        "runtime": runtime,
        "audit": audit,
        "governance": governance,
        "evidence": evidence,
        "recommendations": recommendations,
        "limitations": notes,
    }


def _blocks(report: dict[str, Any]) -> list[tuple[str, list[str]]]:
    sections = [
        ("Executive summary", [
            f"Period: {report['since_utc'] or 'all recorded history'} to {report['until_utc']} UTC",
            f"Current inventory: {report['inventory']['servers']} servers, {report['inventory']['tools']} tools",
            f"Observed: {report['tool_security']['findings']} tool-analysis findings, "
            f"{report['build_security']['findings']} build findings, "
            f"{report['cloud_security']['findings']} cloud findings",
            f"Recorded Runtime outcome rows: {report['runtime']['events']}",
        ]),
        ("MCP Inventory & Trust", [
            f"Servers: {report['inventory']['servers']} | Trust: {report['inventory']['server_trust']}",
            f"Tools: {report['inventory']['tools']} | Review states: {report['inventory']['tool_reviews']}",
            f"Tool risk: {report['inventory']['tool_risk']}",
        ]),
        ("Tool Security Analysis", [
            f"Analyses: {report['tool_security']['analyses']} | Status: {report['tool_security']['status']}",
            f"Drift: {report['tool_security']['drift']}",
            f"Findings: {report['tool_security']['findings']} | Severity: {report['tool_security']['severity']}",
        ]),
        ("Build Security", [
            f"Scans: {report['build_security']['scans']} | Status: {report['build_security']['scan_status']}",
            f"Assessments: {report['build_security']['assessments']}",
            f"Findings: {report['build_security']['findings']} | Severity: {report['build_security']['severity']}",
        ]),
        ("Cloud & Deploy Security", [
            f"Scans: {report['cloud_security']['scans']} | Status: {report['cloud_security']['scan_status']}",
            f"Source kinds: {report['cloud_security']['scan_kind']}",
            f"Findings: {report['cloud_security']['findings']} | Severity: {report['cloud_security']['severity']}",
            f"Recorded IAM comparison statuses: {report['cloud_security']['iam_comparisons']}",
        ]),
        ("Runtime Security", [
            f"Outcome rows: {report['runtime']['events']}",
            f"Outcome taxonomy: {report['runtime']['outcomes']}",
            f"Decisions: {report['runtime']['decisions']}",
            f"OPA decisions: {report['runtime']['opa_decisions']}",
        ]),
        ("Audit & Governance", [
            f"Audit events: {report['audit']['events']} | Results: {report['audit']['results']}",
            f"Recorded actions: {report['audit']['actions']}",
            f"Active emergency restrictions: {report['governance']['active_emergency_restrictions']}",
            f"Latest recorded published revision: {report['governance']['published_revision_number'] or 'Not recorded'}",
        ]),
        ("Findings & Recommendations", list(report["recommendations"])),
    ]
    if report["evidence"]:
        lines = []
        for name, rows in report["evidence"].items():
            lines.append(f"{name}: {len(rows)} recent safe record IDs (maximum {MAX_EVIDENCE_PER_SECTION})")
            lines += [f"  {r['reference']} | {r['time_utc']} | {r['status']}" for r in rows]
        sections.append(("Evidence Appendix — Redacted References", lines))
    sections.append(("Evidence Limits", list(report["limitations"])))
    return sections


def render_html(report: dict[str, Any]) -> bytes:
    esc = lambda value: html.escape(str(value), quote=True)
    cards = [
        ("MCP servers", report["inventory"]["servers"]),
        ("MCP tools", report["inventory"]["tools"]),
        ("Runtime rows", report["runtime"]["events"]),
        ("Build findings", report["build_security"]["findings"]),
        ("Cloud findings", report["cloud_security"]["findings"]),
    ]
    body = []
    for heading, lines in _blocks(report):
        body.append(f"<section><h2>{esc(heading)}</h2>")
        if not lines:
            body.append("<p>No evidence recorded within this report scope.</p>")
        else:
            body.append("<ul>" + "".join(f"<li>{esc(line)}</li>" for line in lines) + "</ul>")
        body.append("</section>")
    metrics = "".join(
        f"<div class='metric'><strong>{esc(value)}</strong><span>{esc(name)}</span></div>"
        for name, value in cards
    )
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>MCP Security Audit Report</title><style>
@page{{size:A4;margin:16mm}}*{{box-sizing:border-box}}
body{{font-family:Arial,sans-serif;color:#142b47;line-height:1.5;max-width:920px;margin:auto}}
header{{background:#102d51;color:#fff;padding:26px 32px}}
h1{{font-size:27px;margin:4px 0}}h2{{color:#153d64;font-size:19px;border-bottom:1px solid #cbd7e5;padding-bottom:7px}}
section{{page-break-inside:avoid;margin:23px 0}}ul{{padding-left:22px}}
li{{overflow-wrap:anywhere;margin:7px 0}}.metrics{{display:flex;flex-wrap:wrap;gap:10px;margin:22px 0}}
.metric{{min-width:145px;flex:1;border:1px solid #d5deed;padding:14px;border-radius:7px}}
.metric strong{{display:block;font-size:24px}}.metric span{{font-size:12px;color:#536a81}}
small{{font-size:11px;color:#627990}}
@media print{{body{{max-width:none}}}}
</style></head><body>
<header><small style="color:#bcd0ed">MCP SECURITY FRAMEWORK · PHASE 9</small>
<h1>Security Audit Report</h1><div>Generated {esc(report['generated_at_utc'])} UTC · {esc(report['period'])}</div></header>
<div class="metrics">{metrics}</div>
{''.join(body)}
<footer><small>Read-only evidence summary · Report ID {esc(report['report_id'])} · This is not a security certification.</small></footer>
</body></html>"""
    return page.encode("utf-8")


def render_json(report: dict[str, Any]) -> bytes:
    return (json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def render_csv(report: dict[str, Any]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(["Section", "Metric", "Recorded value", "Scope"])
    writer.writerow(["Report", "ID", report["report_id"], report["period"]])
    for heading, lines in _blocks(report):
        for line in lines or ["No evidence recorded within this report scope."]:
            # Static labels and safe aggregated status values only; still guard spreadsheet formula interpretation.
            cell = line if not line.startswith(("=", "+", "-", "@")) else "'" + line
            writer.writerow([heading, "Recorded observation", cell, report["period"]])
    return ("\ufeff" + buffer.getvalue()).encode("utf-8")


def _pdf_escape(value: str) -> bytes:
    # Helvetica + WinAnsi PDF font: transliterate unsupported glyphs safely.
    normalized = value.encode("cp1252", "replace").decode("cp1252")
    normalized = normalized.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return normalized.encode("cp1252", "replace")


def render_pdf(report: dict[str, Any]) -> bytes:
    """Dependency-free multipage, selectable-text A4 PDF with valid xref."""
    line_items: list[tuple[str, str]] = []
    for section, values in _blocks(report):
        line_items.append(("section", section))
        if not values:
            line_items.append(("body", "No evidence recorded within this report scope."))
        for item in values:
            for piece in textwrap.wrap(
                str(item), width=91, break_long_words=True, break_on_hyphens=False,
            ) or [""]:
                line_items.append(("body", piece))
        line_items.append(("space", ""))

    pages: list[list[tuple[str, str]]] = [[]]
    used = 0
    for kind, value in line_items:
        height = 23 if kind == "section" else (10 if kind == "space" else 15)
        if used + height > 668 and pages[-1]:
            pages.append([])
            used = 0
        pages[-1].append((kind, value))
        used += height

    objects: list[bytes] = [b""]  # PDF object indexing begins at 1
    def put(data: bytes) -> int:
        objects.append(data)
        return len(objects) - 1

    catalog_id = put(b"")
    pages_id = put(b"")
    font_body = put(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    font_bold = put(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    kids = []
    for index, entries in enumerate(pages, 1):
        commands = [
            b"0.07 0.17 0.31 rg 0 776 595 66 re f",
            b"BT /F2 18 Tf 40 811 Td (MCP Security Audit Report) Tj ET",
            b"BT /F1 9 Tf 40 790 Td (" +
            _pdf_escape(f"Phase 9 | {report['period']} | generated {report['generated_at_utc']} UTC") +
            b") Tj ET",
        ]
        y = 752
        for kind, value in entries:
            if kind == "space":
                y -= 10
                continue
            if kind == "section":
                y -= 22
                commands.extend([
                    f"0.10 0.26 0.43 rg 40 {y-4} 515 1 re f".encode("ascii"),
                    b"BT /F2 12 Tf 40 " + str(y+3).encode() +
                    b" Td (" + _pdf_escape(value) + b") Tj ET",
                ])
            else:
                y -= 15
                commands.append(
                    b"BT /F1 9 Tf 45 " + str(y).encode() +
                    b" Td (" + _pdf_escape(value) + b") Tj ET"
                )
        commands.append(
            b"BT /F1 8 Tf 40 31 Td (" +
            _pdf_escape(f"Report {report['report_id'][:8]} | page {index}/{len(pages)} | evidence summary, not certification") +
            b") Tj ET"
        )
        stream = b"\n".join(commands) + b"\n"
        stream_id = put(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"endstream")
        page_id = put(
            b"<< /Type /Page /Parent " + str(pages_id).encode() + b" 0 R"
            b" /MediaBox [0 0 595 842] /Resources << /Font << /F1 " +
            str(font_body).encode() + b" 0 R /F2 " + str(font_bold).encode() +
            b" 0 R >> >> /Contents " + str(stream_id).encode() + b" 0 R >>"
        )
        kids.append(page_id)
    objects[pages_id] = (
        b"<< /Type /Pages /Kids [" +
        b" ".join(str(x).encode() + b" 0 R" for x in kids) +
        b"] /Count " + str(len(kids)).encode() + b" >>"
    )
    objects[catalog_id] = b"<< /Type /Catalog /Pages " + str(pages_id).encode() + b" 0 R >>"
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for idx, data in enumerate(objects[1:], 1):
        offsets.append(out.tell())
        out.write(f"{idx} 0 obj\n".encode("ascii"))
        out.write(data + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objects)}\n".encode("ascii"))
    out.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.write(
        b"trailer\n<< /Size " + str(len(objects)).encode() +
        b" /Root " + str(catalog_id).encode() + b" 0 R >>\nstartxref\n" +
        str(xref).encode() + b"\n%%EOF\n"
    )
    return out.getvalue()


def render_report(report: dict[str, Any], report_format: str) -> tuple[bytes, str, str]:
    if report_format not in FORMAT_TYPES:
        raise ValueError("unsupported_report_format")
    renderers = {"pdf": render_pdf, "html": render_html, "json": render_json, "csv": render_csv}
    payload = renderers[report_format](report)
    media_type, extension = FORMAT_TYPES[report_format]
    return payload, media_type, f"mcp-security-audit-{report['period']}-{report['report_id'][:8]}.{extension}"

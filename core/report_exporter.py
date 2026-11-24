from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core.paths import resource_path
from core.policy_engine import PolicyEngine
from core.quarantine import Quarantine


class SecurityReportExporter:
    def __init__(self, policy: PolicyEngine, quarantine: Quarantine, license_status: dict[str, Any]) -> None:
        self.policy = policy
        self.quarantine = quarantine
        self.license_status = license_status

    def report_data(self, findings: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
        metadata = json.loads(resource_path("app_metadata.json").read_text(encoding="utf-8"))
        events = self.policy.read_audit(2000)
        finding_items = list(findings)
        return {
            "product": metadata["name"],
            "version": metadata["version"],
            "developer": metadata["developer"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "edition": self.license_status.get("edition", "community"),
            "security_profile": self.policy.get_security_profile(),
            "summary": {
                "audit_event_count": len(events),
                "quarantined_item_count": len(self.quarantine.list_items()),
                "finding_count": len(finding_items),
            },
            "findings": finding_items,
            "quarantine": self.quarantine.list_items(),
            "events": events,
        }

    def export_json(self, destination: Path | str, findings: Iterable[dict[str, Any]] = ()) -> Path:
        output = Path(destination).expanduser()
        if output.suffix.lower() != ".json":
            raise ValueError("JSON audit reports must use the .json extension")
        return self._write_atomic(output, json.dumps(self.report_data(findings), ensure_ascii=False, indent=2) + "\n")

    def export_html(
        self,
        destination: Path | str,
        findings: Iterable[dict[str, Any]] = (),
        language: str = "en-US",
    ) -> Path:
        output = Path(destination).expanduser()
        if output.suffix.lower() not in {".html", ".htm"}:
            raise ValueError("HTML audit reports must use the .html or .htm extension")
        data = self.report_data(findings)
        translations = json.loads(resource_path("i18n/translations.json").read_text(encoding="utf-8"))
        if language not in translations:
            raise ValueError(f"Unsupported report language: {language}")
        labels = translations[language]
        text = lambda key: html.escape(str(labels[key]))
        rows = []
        for event in reversed(data["events"]):
            details = {key: value for key, value in event.items() if key not in {"timestamp", "event"}}
            rows.append(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code></td></tr>".format(
                    html.escape(str(event.get("timestamp", ""))),
                    html.escape(str(event.get("event", ""))),
                    html.escape(json.dumps(details, ensure_ascii=False, default=str)),
                )
            )
        table_rows = "\n".join(rows) or f'<tr><td colspan="3">{text("report_no_events")}</td></tr>'
        finding_rows = []
        for finding in data["findings"]:
            finding_rows.append(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>".format(
                    html.escape(str(finding.get("target", ""))),
                    html.escape(str(finding.get("risk_score", ""))),
                    html.escape(str(finding.get("severity", ""))),
                    html.escape(", ".join(str(rule) for rule in finding.get("matched_rules", []))),
                )
            )
        finding_table_rows = "\n".join(finding_rows) or f'<tr><td colspan="4">{text("report_no_findings")}</td></tr>'
        page = f"""<!doctype html>
<html lang="{html.escape(language)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{html.escape(data['product'])} {text("report_title")}</title>
<style>
body{{margin:0;background:#0B0F17;color:#E7EDF5;font:15px Segoe UI,Arial,sans-serif}}
main{{max-width:1100px;margin:36px auto;padding:30px;background:#131A26;border:1px solid #223047;border-radius:14px}}
h1{{margin:0;color:#10B981}}h2{{margin-top:32px;color:#E79E29}}.muted{{color:#91A0B4}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap}}.tile{{padding:14px 18px;background:#182232;border:1px solid #223047;border-radius:9px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:11px;text-align:left;border-bottom:1px solid #223047;vertical-align:top}}
th{{color:#10B981}}code{{white-space:pre-wrap;overflow-wrap:anywhere;color:#C9D5E4}}
</style></head><body><main>
<h1>AI FBI {text("report_title")}</h1>
<p class="muted">{text("report_prepared_by")} Ali Kouhzardi · {text("report_version")} {html.escape(str(data['version']))} · {html.escape(str(data['generated_at']))}</p>
<div class="tiles">
<div class="tile">{text("edition_status")}<br><strong>{html.escape(str(data['edition']).title())}</strong></div>
<div class="tile">{text("security_profile")}<br><strong>{html.escape(str(data['security_profile']))}</strong></div>
<div class="tile">{text("report_events")}<br><strong>{data['summary']['audit_event_count']}</strong></div>
<div class="tile">{text("report_quarantined")}<br><strong>{data['summary']['quarantined_item_count']}</strong></div>
<div class="tile">{text("report_findings")}<br><strong>{data['summary']['finding_count']}</strong></div>
</div>
<h2>{text("report_recent_activity")}</h2>
<table><thead><tr><th>{text("report_time")}</th><th>{text("report_event")}</th><th>{text("report_details")}</th></tr></thead><tbody>{table_rows}</tbody></table>
<h2>{text("report_findings")}</h2>
<table><thead><tr><th>{text("report_target")}</th><th>{text("report_score")}</th><th>{text("report_severity")}</th><th>{text("report_rules")}</th></tr></thead><tbody>{finding_table_rows}</tbody></table>
<p class="muted">{text("accuracy_heuristic_disclaimer")}</p>
</main></body></html>"""
        return self._write_atomic(output, page)

    @staticmethod
    def _write_atomic(output: Path, content: str) -> Path:
        output.parent.mkdir(parents=True, exist_ok=True)
        temp = output.with_suffix(output.suffix + ".tmp")
        temp.write_text(content, encoding="utf-8")
        temp.replace(output)
        return output

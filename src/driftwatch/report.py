import json
from datetime import datetime, timezone
from typing import Any

from .models import Finding, Inventory


def build_report(inventories: list[Inventory], findings: list[Finding]) -> dict[str, Any]:
    return {
        "format_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": [{"name": x.target, "object_count": len(x.objects), "errors": x.errors} for x in inventories],
        "summary": {"finding_count": len(findings), "error_count": sum(len(x.errors) for x in inventories)},
        "findings": [x.as_dict() for x in findings],
    }


def write_json(report: dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")

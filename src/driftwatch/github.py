"""Small, dependency-free GitHub Actions renderers."""

from urllib.parse import quote

from .models import Finding


def job_summary(findings: list[Finding], targets: tuple[str, ...] = (), limit: int = 20) -> str:
    lines = ["## Driftwatch schema report", "", f"Findings: **{len(findings)}**"]
    if targets:
        lines.append(f"Targets: `{', '.join(targets)}`")
    lines.extend(["", "| Severity | Kind | Object | Message |", "|---|---|---|---|"])
    for finding in findings[:limit]:
        message = finding.message.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{finding.severity}` | `{finding.kind}` | `{finding.object_name}` | {message} |")
    if len(findings) > limit:
        lines.extend(["", f"_Showing {limit} of {len(findings)} findings; see the uploaded full report._"])
    return "\n".join(lines) + "\n"


def annotations(findings: list[Finding], limit: int = 50) -> str:
    level = {"info": "notice", "warning": "warning", "breaking": "error", "critical": "error"}
    lines = []
    for finding in findings[:limit]:
        title = quote(f"driftwatch: {finding.kind}", safe=" :_-|")
        message = quote(f"{finding.object_type}|{finding.object_name}: {finding.message}", safe=" :_.,|()[]'\"")
        lines.append(f"::{level.get(finding.severity, 'warning')} title={title}::{message}")
    return "\n".join(lines) + ("\n" if lines else "")

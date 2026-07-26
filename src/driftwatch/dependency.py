"""Conservative dependency graph and bounded impact analysis."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from .models import Finding, ObjectId


@dataclass
class DependencyGraph:
    edges: dict[ObjectId, set[ObjectId]] = field(default_factory=lambda: defaultdict(set))

    def add(self, dependency: ObjectId, dependent: ObjectId) -> None:
        self.edges[dependency].add(dependent)
        self.edges.setdefault(dependent, set())

    def dependents(self, node: ObjectId, depth: int | None = None) -> set[ObjectId]:
        result: set[ObjectId] = set()
        queue = deque([(node, 0)])
        while queue:
            current, level = queue.popleft()
            if depth is not None and level >= depth:
                continue
            for child in self.edges.get(current, set()):
                if child not in result:
                    result.add(child)
                    queue.append((child, level + 1))
        return result

    def dependencies(self, node: ObjectId, depth: int | None = None) -> set[ObjectId]:
        reverse = DependencyGraph()
        for source, targets in self.edges.items():
            for target in targets:
                reverse.add(target, source)
        return reverse.dependents(node, depth)

    def as_dict(self) -> dict[str, list[str]]:
        return {
            str(source): sorted(map(str, targets))
            for source, targets in sorted(self.edges.items(), key=lambda x: str(x[0]))
        }


def graph_from_inventory(inventory: Any) -> DependencyGraph:
    graph = DependencyGraph()
    for key, value in inventory.objects.items():
        try:
            node = ObjectId.parse(key)
        except ValueError:
            continue
        if node.type == "CONSTRAINT" and value.get("referenced_schema") and value.get("referenced_table"):
            graph.add(
                ObjectId("TABLE", value["referenced_schema"], value["referenced_table"]),
                ObjectId("TABLE", node.schema, node.name),
            )
        for dependency in value.get("dependencies", []):
            try:
                graph.add(ObjectId.parse(dependency), node)
            except (TypeError, ValueError):
                continue
    return graph


def impact_for_finding(finding: Finding, graph: DependencyGraph, depth: int = 3) -> dict[str, Any]:
    try:
        node = ObjectId.parse(f"{finding.object_type}|{finding.object_name}")
    except ValueError:
        return {"direct_dependents": 0, "indirect_dependents": 0, "blast_radius": 0, "affected_objects": []}
    candidates = [node]
    if node.type in {"COLUMN", "INDEX", "CONSTRAINT"}:
        candidates.append(ObjectId("TABLE", node.schema, node.name))
    direct: set[ObjectId] = set()
    all_dependents: set[ObjectId] = set()
    for candidate in candidates:
        direct.update(graph.dependents(candidate, 1))
        all_dependents.update(graph.dependents(candidate, max(1, depth)))
    return {
        "direct_dependents": len(direct),
        "indirect_dependents": max(0, len(all_dependents) - len(direct)),
        "blast_radius": len(all_dependents),
        "affected_objects": sorted(map(str, all_dependents)),
    }


def add_impact(findings: list[Finding], graph: DependencyGraph, depth: int = 3) -> list[Finding]:
    return [
        Finding(**{**finding.__dict__, "impact": impact_for_finding(finding, graph, depth)}) for finding in findings
    ]

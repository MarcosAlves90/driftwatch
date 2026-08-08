"""Conservative dependency graph and bounded, target-aware impact analysis."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import CollectionSection, CollectionStatus, Finding, Inventory, ObjectId


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
                if child not in result and child != node:
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
            for source, targets in sorted(self.edges.items(), key=lambda item: str(item[0]))
        }


def _parse_object(value: Any) -> ObjectId | None:
    try:
        return ObjectId.parse(str(value))
    except (TypeError, ValueError):
        return None


def _add_explicit_edges(graph: DependencyGraph, inventory: Any) -> None:
    for edge in getattr(inventory, "dependencies", ()) or ():
        dependency = _parse_object(edge.get("dependency"))
        dependent = _parse_object(edge.get("dependent"))
        if dependency is not None and dependent is not None:
            graph.add(dependency, dependent)


def _add_object_edges(graph: DependencyGraph, inventory: Any) -> None:
    for key, value in inventory.objects.items():
        node = _parse_object(key)
        if node is None:
            continue
        referenced_schema = value.get("referenced_schema")
        referenced_table = value.get("referenced_table")
        if node.type == "CONSTRAINT" and referenced_schema and referenced_table:
            graph.add(ObjectId("TABLE", referenced_schema, referenced_table), ObjectId("TABLE", node.schema, node.name))
        for dependency_value in value.get("dependencies", []):
            dependency = _parse_object(dependency_value)
            if dependency is not None:
                graph.add(dependency, node)


def graph_from_inventory(inventory: Any) -> DependencyGraph:
    graph = DependencyGraph()
    _add_explicit_edges(graph, inventory)
    _add_object_edges(graph, inventory)
    return graph


def _candidate_nodes(finding: Finding) -> list[ObjectId]:
    try:
        node = ObjectId.parse(f"{finding.object_type}|{finding.object_name}")
    except ValueError:
        return []
    candidates = [node]
    if node.type in {"COLUMN", "INDEX", "CONSTRAINT"}:
        candidates.append(ObjectId("TABLE", node.schema, node.name))
    return candidates


def impact_for_finding(finding: Finding, graph: DependencyGraph, depth: int = 3) -> dict[str, Any]:
    direct: set[ObjectId] = set()
    all_dependents: set[ObjectId] = set()
    for candidate in _candidate_nodes(finding):
        direct.update(graph.dependents(candidate, 1))
        all_dependents.update(graph.dependents(candidate, max(1, depth)))
    return {
        "direct_dependents": len(direct),
        "indirect_dependents": max(0, len(all_dependents) - len(direct)),
        "blast_radius": len(all_dependents),
        "affected_objects": sorted(map(str, all_dependents)),
    }


def dependency_coverage(inventory: Inventory) -> str:
    explicit = inventory.metadata.get("dependency_coverage")
    if explicit in {"complete", "partial", "unavailable"}:
        return explicit
    section = inventory.sections.get(CollectionSection.DEPENDENCIES.value)
    if section is None:
        return "partial" if inventory.dependencies else "unknown"
    return "complete" if section.status == CollectionStatus.SUCCESS else "unavailable"


def add_impact(findings: list[Finding], graph: DependencyGraph, depth: int = 3) -> list[Finding]:
    return [
        Finding(**{**finding.__dict__, "impact": impact_for_finding(finding, graph, depth)}) for finding in findings
    ]


def add_target_impact(findings: Iterable[Finding], inventories: Iterable[Inventory], depth: int = 3) -> list[Finding]:
    """Attach impact computed independently for every comparison target."""
    inventory_by_target = {inventory.target: inventory for inventory in inventories}
    graphs = {target: graph_from_inventory(inventory) for target, inventory in inventory_by_target.items()}
    result: list[Finding] = []
    for finding in findings:
        targets = finding.comparison or finding.targets
        by_target: dict[str, Any] = {}
        affected: set[str] = set()
        max_direct = max_indirect = max_blast = 0
        for target in dict.fromkeys(targets):
            inventory = inventory_by_target.get(target)
            graph = graphs.get(target)
            if inventory is None or graph is None:
                continue
            impact = impact_for_finding(finding, graph, depth)
            impact["coverage"] = dependency_coverage(inventory)
            by_target[target] = impact
            max_direct = max(max_direct, int(impact["direct_dependents"]))
            max_indirect = max(max_indirect, int(impact["indirect_dependents"]))
            max_blast = max(max_blast, int(impact["blast_radius"]))
            affected.update(impact["affected_objects"])
        combined = {
            "direct_dependents": max_direct,
            "indirect_dependents": max_indirect,
            "blast_radius": max_blast,
            "affected_objects": sorted(affected),
            "by_target": by_target,
        }
        result.append(Finding(**{**finding.__dict__, "impact": combined}))
    return result


def dependency_view(
    inventory: Inventory,
    object_id: ObjectId,
    *,
    direction: str = "dependents",
    depth: int = 3,
) -> dict[str, Any]:
    if direction not in {"dependents", "dependencies"}:
        raise ValueError("direction must be dependents or dependencies")
    if depth < 0:
        raise ValueError("dependency depth must not be negative")
    graph = graph_from_inventory(inventory)
    values = graph.dependents(object_id, depth) if direction == "dependents" else graph.dependencies(object_id, depth)
    return {
        "target": inventory.target,
        "object": str(object_id),
        "direction": direction,
        "depth": depth,
        "coverage": dependency_coverage(inventory),
        "objects": sorted(map(str, values)),
    }

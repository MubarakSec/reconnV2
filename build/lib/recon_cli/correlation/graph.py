from __future__ import annotations

import json
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass
class GraphNode:
    type: str
    id: str
    attrs: Dict[str, object] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: Tuple[str, str]
    target: Tuple[str, str]
    label: str
    attrs: Dict[str, object] = field(default_factory=dict)


class Graph:
    def __init__(self) -> None:
        self._nodes: Dict[Tuple[str, str], GraphNode] = {}
        self._edges: Dict[Tuple[str, str, str, str, str], GraphEdge] = {}
        self._adjacency: Dict[Tuple[str, str], set[Tuple[str, str]]] = defaultdict(set)

    def add_node(self, node_type: str, node_id: str, **attrs: object) -> GraphNode:
        key = (node_type, node_id)
        node = self._nodes.get(key)
        if node is None:
            node = GraphNode(node_type, node_id, {})
            self._nodes[key] = node
        for k, v in attrs.items():
            if v is None:
                continue
            if isinstance(v, list) and not v:
                continue
            node.attrs[k] = v
        return node

    def add_edge(
        self,
        src_type: str,
        src_id: str,
        label: str,
        dst_type: str,
        dst_id: str,
        **attrs: object,
    ) -> GraphEdge:
        self.add_node(src_type, src_id)
        self.add_node(dst_type, dst_id)
        key = (src_type, src_id, label, dst_type, dst_id)
        edge = self._edges.get(key)
        if edge is None:
            edge = GraphEdge((src_type, src_id), (dst_type, dst_id), label, {})
            self._edges[key] = edge
            self._adjacency[(src_type, src_id)].add((dst_type, dst_id))
            self._adjacency[(dst_type, dst_id)].add((src_type, src_id))
        for k, v in attrs.items():
            if v is None:
                continue
            edge.attrs[k] = v
        return edge

    def to_dict(self) -> Dict[str, object]:
        return {
            "nodes": [
                {
                    "type": node.type,
                    "id": node.id,
                    "attrs": node.attrs,
                }
                for node in self._nodes.values()
            ],
            "edges": [
                {
                    "source": {"type": edge.source[0], "id": edge.source[1]},
                    "target": {"type": edge.target[0], "id": edge.target[1]},
                    "label": edge.label,
                    "attrs": edge.attrs,
                }
                for edge in self._edges.values()
            ],
        }

    def nodes(self) -> Iterable[GraphNode]:
        return self._nodes.values()

    def degree_counts(
        self, node_type: Optional[str] = None
    ) -> Dict[Tuple[str, str], int]:
        counts: Dict[Tuple[str, str], int] = {}
        for key in self._nodes.keys():
            if node_type and key[0] != node_type:
                continue
            counts[key] = len(self._adjacency.get(key, set()))
        return counts

    def top_connected(
        self, limit: int = 10, node_type: Optional[str] = None
    ) -> List[Dict[str, object]]:
        counts = self.degree_counts(node_type=node_type)
        ordered = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
        results: List[Dict[str, object]] = []
        for (node_type_value, node_id), degree in ordered:
            node = self._nodes[(node_type_value, node_id)]
            results.append(
                {
                    "type": node_type_value,
                    "id": node_id,
                    "degree": degree,
                    "attrs": node.attrs,
                }
            )
        return results

    def to_dot(self) -> str:
        lines = ["digraph correlation {"]
        for node in self._nodes.values():
            label = f"{node.type}:{node.id}"
            lines.append(f'  "{node.type}:{node.id}" [label="{label}"];')
        for edge in self._edges.values():
            src = f"{edge.source[0]}:{edge.source[1]}"
            dst = f"{edge.target[0]}:{edge.target[1]}"
            label = edge.label
            lines.append(f'  "{src}" -> "{dst}" [label="{label}"];')
        lines.append("}")
        return "\n".join(lines)

    def save_dot(self, path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_dot(), encoding="utf-8")

    def save_svg(self, path) -> bool:
        dot_exe = shutil.which("dot")
        if not dot_exe:
            return False
        dot_path = path.with_suffix(".dot")
        self.save_dot(dot_path)
        try:
            subprocess.run(
                [dot_exe, "-Tsvg", str(dot_path), "-o", str(path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            return False
        return True

    def save(self, path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

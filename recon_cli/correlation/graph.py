from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


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

    def save(self, path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

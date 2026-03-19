from __future__ import annotations

from copy import deepcopy
from typing import Any


_EMPTY_OBJECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}


def normalize_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize a JSON schema for machine-facing export.

    This keeps permissive free-form objects intact, but closes object schemas that
    declare explicit properties and inlines mixed `$ref` objects for cleaner consumers.
    """
    if not schema:
        return dict(_EMPTY_OBJECT_SCHEMA)
    normalized = deepcopy(schema)
    return _normalize_json_schema(normalized, root=normalized)


def _normalize_json_schema(
    json_schema: object, *, root: dict[str, object]
) -> dict[str, Any]:
    if not isinstance(json_schema, dict):
        raise TypeError(f"Expected schema dictionary, got {type(json_schema).__name__}")

    defs = json_schema.get("$defs")
    if isinstance(defs, dict):
        for def_schema in defs.values():
            _normalize_json_schema(def_schema, root=root)

    definitions = json_schema.get("definitions")
    if isinstance(definitions, dict):
        for def_schema in definitions.values():
            _normalize_json_schema(def_schema, root=root)

    ref = json_schema.get("$ref")
    if isinstance(ref, str) and len(json_schema) > 1:
        resolved = _resolve_ref(root=root, ref=ref)
        if not isinstance(resolved, dict):
            raise TypeError(f"Schema ref {ref!r} did not resolve to an object")
        json_schema.update({**resolved, **json_schema})
        json_schema.pop("$ref", None)

    properties = json_schema.get("properties")
    if isinstance(properties, dict):
        json_schema["type"] = "object"
        if "additionalProperties" not in json_schema:
            json_schema["additionalProperties"] = False
        json_schema["properties"] = {
            key: _normalize_json_schema(value, root=root)
            for key, value in properties.items()
        }
    elif (
        json_schema.get("type") == "object"
        and "additionalProperties" not in json_schema
    ):
        json_schema["additionalProperties"] = False

    additional_properties = json_schema.get("additionalProperties")
    if isinstance(additional_properties, dict):
        json_schema["additionalProperties"] = _normalize_json_schema(
            additional_properties, root=root
        )

    items = json_schema.get("items")
    if isinstance(items, dict):
        json_schema["items"] = _normalize_json_schema(items, root=root)

    for key in ("anyOf", "allOf", "oneOf"):
        value = json_schema.get(key)
        if isinstance(value, list):
            json_schema[key] = [
                _normalize_json_schema(entry, root=root)
                if isinstance(entry, dict)
                else entry
                for entry in value
            ]

    return json_schema


def _resolve_ref(*, root: dict[str, object], ref: str) -> object:
    if not ref.startswith("#/"):
        raise ValueError(f"Unsupported ref format: {ref}")
    resolved: object = root
    for part in ref[2:].split("/"):
        if not isinstance(resolved, dict):
            raise TypeError(f"Cannot resolve {ref!r}; hit non-object at {part!r}")
        resolved = resolved[part]
    return resolved

"""A JSON Schema to a pydantic model, for the two frameworks that insist on one.

CrewAI's `BaseTool.args_schema` and AutoGen's `BaseTool.args_type` are pydantic model
*types*, not schemas; LangChain and the OpenAI Agents SDK take the schema as it is. The
door forwards each tool's `inputSchema` from the vetted connector, so this is the
smallest honest conversion: the declared properties, typed where the type is one of JSON
Schema's six, `Any` otherwise, required where the schema says so and optional otherwise.
Nested object shapes are not modelled beyond `dict`; the door validates the arguments
against the real schema on the call, so a model that sends the wrong shape is told so by
the door rather than by this file.

Imported lazily by the two adapters that need it: pydantic is a dependency of both of
those frameworks and of neither this package nor the other two adapters.
"""

from __future__ import annotations

import keyword
import re
from typing import Any, Optional

_JSON_TYPES: dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "array": list,
    "object": dict,
}


def _python_type(spec: Any) -> Any:
    if not isinstance(spec, dict):
        return Any
    declared = spec.get("type")
    if isinstance(declared, list):
        # `["string", "null"]` and the like: the first non-null type, optional.
        declared = next((t for t in declared if t != "null"), None)
    return _JSON_TYPES.get(declared, Any)


def model_name(tool_name: str) -> str:
    """`jira_search_issues` → `JiraSearchIssuesArgs`. A class name has to be an
    identifier; a tool name only has to be a string."""
    words = [w for w in re.split(r"[^0-9A-Za-z]+", tool_name) if w]
    return "".join(w[:1].upper() + w[1:] for w in words or ["Tool"]) + "Args"


# Names pydantic will not take as a field: anything with a leading underscore (it becomes
# a private attribute, or raises), anything in the `model_` namespace, anything that is
# not an identifier, and the BaseModel attributes a field would shadow. A connector's
# schema is the vendor's and may have any of these — `_hidden` was in a real one — so
# every such property becomes a field with a safe Python name and the original as its
# alias. The model sees the alias (that is what `model_json_schema` emits), the door
# receives the alias (`arguments_from` dumps by alias), and the Python name is nobody's
# business.
_SHADOWED = frozenset(
    {"schema", "json", "dict", "copy", "validate", "construct", "fields", "parse_obj", "from_orm", "update_forward_refs"}
)


def field_name_for(key: str) -> str:
    safe = re.sub(r"\W", "_", key).lstrip("_")
    if not safe:
        return "f"
    if not safe[0].isalpha():
        safe = "f_" + safe
    if safe.startswith("model_") or safe in _SHADOWED or keyword.iskeyword(safe):
        safe = "f_" + safe
    return safe


def model_from_schema(tool_name: str, schema: dict[str, Any]) -> type:
    from pydantic import ConfigDict, Field, create_model

    properties = schema.get("properties") if isinstance(schema, dict) else None
    properties = properties if isinstance(properties, dict) else {}
    required = set(schema.get("required") or ()) if isinstance(schema, dict) else set()

    fields: dict[str, Any] = {}
    taken: set[str] = set()
    for key, spec in properties.items():
        name = field_name_for(key)
        while name in taken:
            name += "_"
        taken.add(name)
        annotation = _python_type(spec)
        description = spec.get("description") if isinstance(spec, dict) else None
        alias = key if key != name else None
        if key in required:
            fields[name] = (annotation, Field(..., description=description, alias=alias))
        else:
            fields[name] = (Optional[annotation], Field(None, description=description, alias=alias))

    # Properties the schema did not declare are passed through rather than refused: the
    # door validates against the connector's real schema, and a schema with no
    # `properties` at all (a tool that takes anything) must not become one that takes
    # nothing. `populate_by_name` lets a caller use either spelling.
    return create_model(
        model_name(tool_name),
        __config__=ConfigDict(extra="allow", populate_by_name=True, protected_namespaces=()),
        **fields,
    )


def arguments_from(model_instance: Any) -> dict[str, Any]:
    """What to send the door: the fields the model set, under the schema's own names,
    without the `None`s that stand for *not given*."""
    return {k: v for k, v in model_instance.model_dump(by_alias=True).items() if v is not None}

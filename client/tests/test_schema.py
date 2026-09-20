"""`_schema.py`: a vendor's JSON Schema to a pydantic model, without losing a name.

Found against a real door on 2026-09-20: a connector advertising a property called
`_hidden` made pydantic raise `NameError` inside `create_model`, which took the CrewAI
and AutoGen adapters down for that whole connector. Every name pydantic cannot take as
a field is aliased; the door sees the schema's own spelling.
"""

from __future__ import annotations

import pytest

pydantic = pytest.importorskip("pydantic")

from carnet_mcp._schema import arguments_from, field_name_for, model_from_schema, model_name  # noqa: E402


def test_names_pydantic_cannot_take_are_aliased_and_round_trip():
    schema = {
        "type": "object",
        "properties": {
            "project": {"type": "string", "description": "the key"},
            "_hidden": {"type": "integer"},
            "model_config": {"type": "string"},
            "weird-name": {"type": ["string", "null"]},
            "schema": {"type": "string"},
            "class": {"type": "boolean"},
            "123": {"type": "number"},
            "ünïcode": {"type": "string"},
        },
        "required": ["project", "_hidden"],
    }
    model = model_from_schema("jira_search_issues", schema)
    assert model.__name__ == "JiraSearchIssuesArgs"
    fields = model.model_fields
    assert fields["project"].is_required() and fields["project"].description == "the key"
    assert fields["hidden"].alias == "_hidden" and fields["hidden"].is_required()
    assert fields["f_model_config"].alias == "model_config"
    assert fields["weird_name"].alias == "weird-name" and not fields["weird_name"].is_required()
    assert fields["f_schema"].alias == "schema"
    assert fields["f_class"].alias == "class"
    assert fields["f_123"].alias == "123"

    # The schema the model sees carries the original names.
    emitted = model.model_json_schema()["properties"]
    assert {"project", "_hidden", "model_config", "weird-name", "schema", "class", "123", "ünïcode"} <= set(emitted)
    assert set(model.model_json_schema()["required"]) == {"project", "_hidden"}

    # Built by the original names (what a framework does), dumped by them (what the door gets).
    instance = model.model_validate({"project": "ACME", "_hidden": 1, "weird-name": "w", "class": True})
    assert arguments_from(instance) == {"project": "ACME", "_hidden": 1, "weird-name": "w", "class": True}
    # ...and by the Python names too.
    assert arguments_from(model(project="ACME", hidden=2)) == {"project": "ACME", "_hidden": 2}


def test_undeclared_properties_pass_through_and_an_empty_schema_takes_anything():
    model = model_from_schema("t", {"type": "object", "properties": {"a": {"type": "string"}}})
    assert arguments_from(model.model_validate({"a": "x", "b": 2})) == {"a": "x", "b": 2}
    anything = model_from_schema("t", {})
    assert arguments_from(anything.model_validate({"q": 1})) == {"q": 1}
    assert arguments_from(model_from_schema("t", {"type": "object", "properties": {}}).model_validate({})) == {}


def test_types_and_type_lists():
    model = model_from_schema("t", {"properties": {
        "s": {"type": "string"}, "i": {"type": "integer"}, "n": {"type": "number"}, "b": {"type": "boolean"},
        "l": {"type": "array"}, "o": {"type": "object"}, "u": {}, "sn": {"type": ["null", "string"]}}, "required": ["s", "i"]})
    ok = model.model_validate({"s": "x", "i": 3, "n": 1.5, "b": True, "l": [1], "o": {"k": 1}, "u": None, "sn": None})
    assert arguments_from(ok) == {"s": "x", "i": 3, "n": 1.5, "b": True, "l": [1], "o": {"k": 1}}
    with pytest.raises(pydantic.ValidationError):
        model.model_validate({"s": "x", "i": "not an int"})
    with pytest.raises(pydantic.ValidationError):
        model.model_validate({"i": 3})


def test_two_properties_that_sanitise_to_the_same_name_stay_distinct():
    model = model_from_schema("t", {"properties": {"a-b": {"type": "string"}, "a_b": {"type": "string"}, "a b": {"type": "string"}}})
    aliases = sorted(f.alias or n for n, f in model.model_fields.items())
    assert aliases == ["a b", "a-b", "a_b"]
    assert arguments_from(model.model_validate({"a-b": "1", "a_b": "2", "a b": "3"})) == {"a-b": "1", "a_b": "2", "a b": "3"}


def test_model_and_field_name_helpers():
    assert model_name("jira_search_issues") == "JiraSearchIssuesArgs"
    assert model_name("github.repo/create-pr") == "GithubRepoCreatePrArgs"
    assert model_name("") == "ToolArgs"
    assert field_name_for("__init__") == "init__"
    assert field_name_for("_hidden") == "hidden" and field_name_for("123") == "f_123" and field_name_for("class") == "f_class"
    assert field_name_for("model_dump") == "f_model_dump"
    assert field_name_for("") == "f"

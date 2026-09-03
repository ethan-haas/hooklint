import pytest

from hooklint.pointer import json_pointer, resolve_pointer, PointerError


def test_json_pointer_basic():
    assert json_pointer([]) == ""
    assert json_pointer(["a"]) == "/a"
    assert json_pointer(["a", 0, "b"]) == "/a/0/b"


def test_json_pointer_escapes_tilde_and_slash():
    assert json_pointer(["a/b"]) == "/a~1b"
    assert json_pointer(["a~b"]) == "/a~0b"


def test_resolve_pointer_dict_and_list():
    doc = {"a": [1, {"b": "c"}]}
    assert resolve_pointer(doc, "") is doc
    assert resolve_pointer(doc, "/a/0") == 1
    assert resolve_pointer(doc, "/a/1/b") == "c"


def test_resolve_pointer_missing_key_raises():
    with pytest.raises(PointerError):
        resolve_pointer({"a": 1}, "/b")


def test_resolve_pointer_index_out_of_range_raises():
    with pytest.raises(PointerError):
        resolve_pointer({"a": [1]}, "/a/5")


def test_resolve_pointer_escaped_segment_roundtrip():
    doc = {"a/b": {"c~d": 1}}
    assert resolve_pointer(doc, "/a~1b/c~0d") == 1

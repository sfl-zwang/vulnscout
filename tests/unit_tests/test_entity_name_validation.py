import pytest

from src.controllers._base import validate_entity_name


@pytest.mark.parametrize("name", ["default", "My_App-1@v2", "A", "9", "x" * 64])
def test_accepts(name):
    assert validate_entity_name(f"  {name}  ", "Project name") == name


@pytest.mark.parametrize("name", ["", "  ", "a b", "a.b", "a+b", "a/b", "a(b)", "-a", "_a", "@a", "é", "x" * 65])
def test_rejects(name):
    with pytest.raises(ValueError):
        validate_entity_name(name, "Project name")

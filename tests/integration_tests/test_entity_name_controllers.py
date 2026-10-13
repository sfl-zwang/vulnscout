import pytest

from src.controllers.projects import ProjectController
from src.controllers.variants import VariantController
from src.models.project import Project
from src.models.variant import Variant


def test_get_or_create_keeps_legacy_names_reachable():
    legacy_project = Project.create("legacy name..")
    legacy_variant = Variant.create("..", legacy_project.id)
    assert ProjectController.get_or_create("legacy name..").id == legacy_project.id
    assert VariantController.get_or_create("..", legacy_project.id).id == legacy_variant.id


def test_get_or_create_validates_new_names():
    with pytest.raises(ValueError):
        ProjectController.get_or_create("new name")
    project = ProjectController.get_or_create("fine")
    with pytest.raises(ValueError):
        VariantController.get_or_create("bad name", project.id)

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.variant import Variant
from ._base import ensure_uuid, resolve_entity, validate_entity_name, validate_non_empty


class VariantController:
    """
    Service layer for Variant CRUD operations.

    Handles input validation, delegates persistence to the :class:`Variant`
    model and provides dictionary serialisation for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(variant: Variant) -> dict:
        """Return a JSON-serialisable dict representation of *variant*."""
        return {
            "id": str(variant.id),
            "name": variant.name,
            "project_id": str(variant.project_id),
        }

    @staticmethod
    def serialize_list(variants: list[Variant]) -> list[dict]:
        """Return a list of serialised variant dicts."""
        return [VariantController.serialize(v) for v in variants]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(variant_id: uuid.UUID | str) -> Optional[Variant]:
        """Return the variant matching *variant_id*, or ``None`` if not found."""
        return Variant.get_by_id(ensure_uuid(variant_id))

    @staticmethod
    def get_all() -> list[Variant]:
        """Return all variants ordered by name."""
        return Variant.get_all()

    @staticmethod
    def get_by_project(project_id: uuid.UUID | str) -> list[Variant]:
        """Return all variants belonging to *project_id*, ordered by name."""
        return Variant.get_by_project(ensure_uuid(project_id))

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(name: str, project_id: uuid.UUID | str) -> Variant:
        """
        Validate *name* and create a new variant under *project_id*.

        :raises ValueError: if *name* is empty, blank or not an allowed name.
        """
        name = validate_entity_name(name, "Variant name")
        return Variant.create(name, ensure_uuid(project_id))

    @staticmethod
    def get_or_create(name: str, project_id: uuid.UUID | str) -> Variant:
        """
        Return an existing variant matching *name* under *project_id*,
        or create and persist a new one.  Only a new name is checked against the
        naming rules, so pre-existing variants stay reachable.

        :raises ValueError: if *name* is empty or blank, or is new and not an allowed name.
        """
        name = validate_non_empty(name, "Variant name")
        project_uuid = ensure_uuid(project_id)
        if Variant.get_by_name_and_project(name, project_uuid) is None:
            name = validate_entity_name(name, "Variant name")
        return Variant.get_or_create(name, project_uuid)

    @staticmethod
    def update(variant: Variant | uuid.UUID | str, name: str) -> Variant:
        """
        Update *variant*'s name.  *variant* may be a :class:`Variant` instance,
        a UUID object, or a UUID string.

        :raises ValueError: if *name* is empty, blank or not an allowed name, or variant is not found.
        """
        name = validate_entity_name(name, "Variant name")
        resolved = resolve_entity(variant, VariantController.get, "Variant")
        return resolved.update(name)

    @staticmethod
    def delete(variant: Variant | uuid.UUID | str) -> None:
        """
        Delete *variant*.  *variant* may be a :class:`Variant` instance,
        a UUID object, or a UUID string.

        :raises ValueError: if the variant is not found.
        """
        resolved = resolve_entity(variant, VariantController.get, "Variant")
        resolved.delete()

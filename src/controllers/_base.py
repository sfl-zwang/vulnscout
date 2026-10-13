# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import re
import typing
import uuid
from typing import Any, Callable, Iterable, Protocol

T = typing.TypeVar("T")
K = typing.TypeVar("K")
V = typing.TypeVar("V", bound="_HasToDict")


class _HasToDict(Protocol):
    def to_dict(self) -> dict[str, Any]:
        ...


def ensure_uuid(value: uuid.UUID | str) -> uuid.UUID:
    """Normalise *value* to a :class:`uuid.UUID`."""
    if isinstance(value, str):
        return uuid.UUID(value)
    return value


def resolve_entity(
    entity: "T | uuid.UUID | str",
    getter: typing.Callable[[uuid.UUID], "T | None"],
    label: str = "Record",
) -> "T":
    """Resolve *entity* to a model instance.

    *entity* may already be a model instance, a UUID, or a UUID string.
    *getter* is a callable that accepts a UUID and returns the
    instance or ``None``.

    :raises ValueError: when the entity cannot be found.
    """
    # If it's not a basic type (UUID / str), assume it's already a model instance.
    if not isinstance(entity, (uuid.UUID, str)):
        return entity
    if isinstance(entity, str):
        entity = uuid.UUID(entity)
    found = getter(entity)
    if found is None:
        raise ValueError(f"{label} not found.")
    return found


def validate_non_empty(value: str, field_name: str) -> str:
    """Strip *value* and raise :class:`ValueError` if it is blank.

    Returns the stripped string.
    """
    value = value.strip()
    if not value:
        raise ValueError(f"{field_name} must not be empty.")
    return value


NAME_MAX_LENGTH = 64
_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_@-]*")


def validate_entity_name(value: str, field_name: str) -> str:
    """Strip *value* and validate it as a new project or variant name.

    Names are 1-64 ASCII characters: letters and digits plus ``_``, ``-`` and ``@``,
    starting with a letter or digit, so they stay safe in URLs, shells and filenames.
    Only apply this to new or renamed entities; existing names are never re-validated.

    :raises ValueError: if the name is blank, too long or contains disallowed characters.
    """
    value = validate_non_empty(value, field_name)
    if len(value) > NAME_MAX_LENGTH:
        raise ValueError(f"{field_name} must be at most {NAME_MAX_LENGTH} characters long.")
    if not _NAME_PATTERN.fullmatch(value):
        raise ValueError(
            f"{field_name} may only contain letters, digits, '_', '-' and '@', "
            "and must start with a letter or digit."
        )
    return value


def to_dict_with_fallback(
    cache: dict[K, V],
    db_get_all: Callable[[], Iterable[V]],
    key_fn: Callable[[V], K],
    label: str,
) -> dict[K, dict[str, Any]]:
    """Return a ``{key: dict}`` mapping preferring *cache* when populated.

    Falls back to *db_get_all* (a callable returning an iterable of model
    records) when *cache* is empty.  *key_fn* extracts the dict key from
    each DB record.  Exceptions are logged via :func:`verbose` using
    *label* for context.
    """
    if cache:
        return {k: v.to_dict() for k, v in cache.items()}
    try:
        return {key_fn(r): r.to_dict() for r in db_get_all()}
    except Exception as e:
        from ..helpers.verbose import verbose
        verbose(f"[{label}.to_dict] {e}")
        return {}

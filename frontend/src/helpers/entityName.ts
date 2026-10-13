// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

export const ENTITY_NAME_MAX_LENGTH = 64;
const ENTITY_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_@-]*$/;

/**
 * Mirror of the backend rule for new or renamed project and variant names.
 * Returns an error message, or null when the (already trimmed) name is acceptable.
 */
export function entityNameError(name: string, label: 'Project' | 'Variant'): string | null {
    if (!name) return `${label} name must not be empty.`;
    if (name.length > ENTITY_NAME_MAX_LENGTH) {
        return `${label} name must be at most ${ENTITY_NAME_MAX_LENGTH} characters long.`;
    }
    if (!ENTITY_NAME_PATTERN.test(name)) {
        return `${label} name may only contain letters, digits, '_', '-' and '@', and must start with a letter or digit.`;
    }
    return null;
}

import { entityNameError } from '../../src/helpers/entityName';

describe('entityNameError', () => {
    test.each(['Apollo', 'a_b-c@d', '9lives', 'x'.repeat(64)])('accepts %s', (name) => {
        expect(entityNameError(name, 'Project')).toBeNull();
    });

    test.each(['has space', 'a.b', 'a+b', 'a/b', '(x)', '-a', '_a', '@a', '..', 'é'])('rejects %s', (name) => {
        expect(entityNameError(name, 'Variant')).toMatch(/^Variant name may only contain/);
    });

    test('rejects empty and overlong names', () => {
        expect(entityNameError('', 'Project')).toBe('Project name must not be empty.');
        expect(entityNameError('x'.repeat(65), 'Project')).toMatch(/at most 64/);
    });
});

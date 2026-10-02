import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import CopilotAssessmentPicker from '../../src/components/CopilotAssessmentPicker';
import VulnModal from '../../src/components/VulnModal';
import OperationQueueModal from '../../src/components/OperationQueueModal';
import { __reset, __setEventSourceFactory } from '../../src/handlers/operationStore';
import type { Operation } from '../../src/types/operation';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';
import Iso8601Duration from '../../src/handlers/iso8601duration';

const variants = [
    { id: 'variant-a', name: 'variant A', project_id: 'project-1' },
    { id: 'variant-b', name: 'variant B', project_id: 'project-1' },
];
const findings = {
    'variant-a': [
        { findingId: 'finding-a1', pkg: 'openssl@3.0.0', outdated: false },
        { findingId: 'finding-a2', pkg: 'openssl@1.0.0', outdated: true },
    ],
    'variant-b': [{ findingId: 'finding-b', pkg: 'zlib@1.0.0', outdated: false }],
};
const pending = [{
    id: 'pending-1', origin: 'ai', variant_ids: ['variant-a'],
    targets: [{ variant_id: 'variant-a', package: 'openssl@1.0.0' }],
}];
const props = {
    projectId: 'project-1', variantId: 'variant-a', vulnId: 'CVE-2026-1234',
    variants, variantFindingsMap: findings, pendingAssessments: pending,
    onStarted: jest.fn(),
    onClose: jest.fn(),
};

class FakeStream {
    private handlers = new Map<string, (event: MessageEvent) => void>();
    addEventListener(type: string, fn: (event: MessageEvent) => void) { this.handlers.set(type, fn); }
    close() {}
    send(type: string, data: unknown) {
        act(() => { this.handlers.get(type)?.({ data: JSON.stringify(data) } as MessageEvent); });
    }
}

const operation = (status: Operation['status'], result: Operation['result'] = null): Operation => ({
    op_id: 'op-1', kind: 'assessment', source: 'copilot', label: 'Assess CVE-2026-1234',
    lane: 'assessment', scope: { project_id: 'project-1' }, status, result, cancellable: true,
    progress: { current: 0, total: 1, message: 'Working' }, logs: [], error: null,
    queue_id: null, position: null, options: {}, created_at: '2026-10-02T10:00:00Z',
    started_at: null, finished_at: null,
});

describe('Copilot assessment picker', () => {
    beforeEach(() => { fetchMock.resetMocks(); });
    afterEach(() => { jest.restoreAllMocks(); __reset(); });

    it('preselects the scoped variant but requires an explicit package and labels historical findings', async () => {
        render(<CopilotAssessmentPicker {...props} pendingAssessments={[]} />);
        expect(screen.getByRole('checkbox', { name: 'variant A' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'variant B' })).not.toBeChecked();
        expect(screen.getByRole('button', { name: 'Start assessment' })).toBeDisabled();
        const options = within(screen.getByLabelText('Package for variant A')).getAllByRole('option');
        expect(options[2]).toHaveTextContent('historical');
        await userEvent.setup().selectOptions(screen.getByLabelText('Package for variant A'), 'openssl@3.0.0');
        expect(screen.getByRole('button', { name: 'Start assessment' })).toBeEnabled();
    });

    it('selects project variants independently and sends exactly one chosen package per variant', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ op_id: 'op-1' }), { status: 202 });
        const onStarted = jest.fn();
        render(<CopilotAssessmentPicker {...props} variantId={undefined} pendingAssessments={[]} onStarted={onStarted} />);
        const user = userEvent.setup();
        await user.click(screen.getByRole('checkbox', { name: 'variant A' }));
        await user.click(screen.getByRole('checkbox', { name: 'variant B' }));
        await user.selectOptions(screen.getByLabelText('Package for variant A'), 'openssl@1.0.0');
        await user.selectOptions(screen.getByLabelText('Package for variant B'), 'zlib@1.0.0');
        await user.click(screen.getByRole('button', { name: 'Start assessment' }));
        await waitFor(() => expect(onStarted).toHaveBeenCalledWith('op-1'));
        expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
            project_id: 'project-1', vuln_id: 'CVE-2026-1234',
            targets: [{ variant_id: 'variant-a', package: 'openssl@1.0.0' }, { variant_id: 'variant-b', package: 'zlib@1.0.0' }],
            replace_pending: false,
        });
    });

    it('warns on a pending assessment anywhere in the variant, requiring acknowledgement', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ op_id: 'op-1' }), { status: 202 });
        render(<CopilotAssessmentPicker {...props} />);
        const user = userEvent.setup();
        await user.selectOptions(screen.getByLabelText('Package for variant A'), 'openssl@3.0.0');
        expect(screen.getByText(/pending AI assessment.*variant A/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Start assessment' })).toBeDisabled();
        await user.click(screen.getByRole('checkbox', { name: /replace pending/i }));
        await user.click(screen.getByRole('button', { name: 'Start assessment' }));
        await waitFor(() => expect(fetchMock).toHaveBeenCalled());
        expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body)).replace_pending).toBe(true);
    });

    it('shows enqueue errors including conflicts without closing the picker', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'An assessment is already active' }), { status: 409 });
        render(<CopilotAssessmentPicker {...props} pendingAssessments={[]} />);
        await userEvent.setup().selectOptions(screen.getByLabelText('Package for variant A'), 'openssl@3.0.0');
        await userEvent.setup().click(screen.getByRole('button', { name: 'Start assessment' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('An assessment is already active');
        expect(props.onClose).not.toHaveBeenCalled();
    });

    it('surfaces an operation failure in the persistent queue', async () => {
        const stream = new FakeStream();
        const restore = __setEventSourceFactory(() => stream as unknown as EventSource);
        render(<OperationQueueModal isOpen onClose={jest.fn()} />);
        stream.send('operation', { ...operation('error'), error: 'Copilot model unavailable' });
        expect(screen.getByRole('alert')).toHaveTextContent('Copilot model unavailable');
        restore();
    });

    it('keeps queued work visible after modal closes and refreshes assessment IDs on completion', async () => {
        const stream = new FakeStream();
        const restore = __setEventSourceFactory(() => stream as unknown as EventSource);
        let completed = false;
        fetchMock.mockResponse(request => {
            const url = String(request.url);
            if (url.includes('/variant-active-packages')) return Promise.resolve(JSON.stringify([
                { variant_id: 'variant-a', active_packages: ['openssl@3.0.0'], findings: [
                    { finding_id: 'finding-a1', package: 'openssl@3.0.0', outdated: false },
                ] },
            ]));
            if (url.includes('/variants')) return Promise.resolve(JSON.stringify([variants[0]]));
            if (url.includes('/copilot-assessments')) return Promise.resolve(JSON.stringify({ op_id: 'op-1' }));
            if (url.includes('/assessments')) return Promise.resolve(JSON.stringify(completed ? [{
                id: 'new-ai-id', vuln_id: 'CVE-2026-1234', origin: 'ai', status: 'under_investigation',
                timestamp: '2026-10-02T11:00:00Z', packages: ['openssl@3.0.0'],
                variant_ids: ['variant-a'], targets: [{ variant_id: 'variant-a', package: 'openssl@3.0.0' }],
                responses: [], status_notes: 'Pending human approval',
            }] : []));
            return Promise.resolve(JSON.stringify({}));
        });
        const vuln = {
            id: 'CVE-2026-1234', packages: ['openssl@3.0.0'], packages_current: ['openssl@3.0.0'],
            aliases: [], related_vulnerabilities: [], urls: [], datasource: '', namespace: 'nvd:cve',
            simplified_status: 'active',
            assessments: [], texts: [], variants: [], cpes: [], found_by: [],
            severity: { cvss: [], severity: 'low', min_score: 1, max_score: 1 },
            epss: { score: 0, percentile: 0 }, fix: { state: 'unknown' },
            effort: {
                optimistic: new Iso8601Duration('PT1H'),
                likely: new Iso8601Duration('PT2H'),
                pessimistic: new Iso8601Duration('PT3H'),
            },
        } as unknown as Vulnerability;
        const modal = () => <VulnModal vuln={vuln} projectId="project-1" variantId="variant-a"
            onClose={jest.fn()} appendAssessment={jest.fn()} appendCVSS={jest.fn()} patchVuln={jest.fn()} />;
        const view = render(modal());
        await userEvent.setup().click(await screen.findByRole('button', { name: 'Assess with Copilot' }));
        await userEvent.setup().selectOptions(screen.getByLabelText('Package for variant A'), 'openssl@3.0.0');
        await userEvent.setup().click(screen.getByRole('button', { name: 'Start assessment' }));
        await waitFor(() => expect(screen.getByText(/assessment queued/i)).toBeInTheDocument());
        view.unmount();
        render(<OperationQueueModal isOpen onClose={jest.fn()} />);
        stream.send('operation', operation('running'));
        expect(screen.getByRole('button', { name: /Assess CVE-2026-1234.*in progress/i })).toBeInTheDocument();
        await userEvent.setup().click(screen.getByRole('button', { name: /Cancel Assess CVE-2026-1234/i }));
        expect(fetchMock.mock.calls.some(([url, init]) => String(url).includes('/op-1/cancel') && init?.method === 'POST')).toBe(true);
        render(modal());
        const before = fetchMock.mock.calls.filter(([url]) => String(url).includes('/assessments')).length;
        completed = true;
        stream.send('operation', operation('done', { assessment_ids: ['new-ai-id'] }));
        await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) => String(url).includes('/assessments')).length).toBeGreaterThan(before));
        await waitFor(() => expect(vuln.assessments.map(a => a.id)).toContain('new-ai-id'));
        restore();
    });

    it('refreshes each successive same-CVE completion and prefers the newly launched operation after reopening', async () => {
        const stream = new FakeStream();
        const restore = __setEventSourceFactory(() => stream as unknown as EventSource);
        let assessmentIds: string[] = [];
        let nextOperationId = 'op-1';
        fetchMock.mockResponse(request => {
            const url = String(request.url);
            if (url.includes('/variant-active-packages')) return Promise.resolve(JSON.stringify([
                { variant_id: 'variant-a', active_packages: ['openssl@3.0.0'], findings: [
                    { finding_id: 'finding-a1', package: 'openssl@3.0.0', outdated: false },
                ] },
            ]));
            if (url.includes('/variants')) return Promise.resolve(JSON.stringify([variants[0]]));
            if (url.includes('/copilot-assessments')) return Promise.resolve(JSON.stringify({ op_id: nextOperationId }));
            if (url.includes('/assessments')) return Promise.resolve(JSON.stringify(assessmentIds.map(id => ({
                id, vuln_id: 'CVE-2026-1234', origin: 'ai', status: 'under_investigation',
                timestamp: '2026-10-02T11:00:00Z', packages: ['openssl@3.0.0'],
                variant_ids: ['variant-a'], targets: [{ variant_id: 'variant-a', package: 'openssl@3.0.0' }],
                responses: [], status_notes: 'Pending human approval',
            }))));
            return Promise.resolve(JSON.stringify({}));
        });
        const vuln = {
            id: 'CVE-2026-1234', packages: ['openssl@3.0.0'], packages_current: ['openssl@3.0.0'],
            aliases: [], related_vulnerabilities: [], urls: [], datasource: '', namespace: 'nvd:cve',
            simplified_status: 'active',
            assessments: [], texts: [], variants: [], cpes: [], found_by: [],
            severity: { cvss: [], severity: 'low', min_score: 1, max_score: 1 },
            epss: { score: 0, percentile: 0 }, fix: { state: 'unknown' },
            effort: {
                optimistic: new Iso8601Duration('PT1H'),
                likely: new Iso8601Duration('PT2H'),
                pessimistic: new Iso8601Duration('PT3H'),
            },
        } as unknown as Vulnerability;
        const modal = () => <VulnModal vuln={vuln} projectId="project-1" variantId="variant-a"
            onClose={jest.fn()} appendAssessment={jest.fn()} appendCVSS={jest.fn()} patchVuln={jest.fn()} />;
        const launch = async () => {
            const user = userEvent.setup();
            await user.click(await screen.findByRole('button', { name: 'Assess with Copilot' }));
            await user.selectOptions(screen.getByLabelText('Package for variant A'), 'openssl@3.0.0');
            const replacePending = screen.queryByRole('checkbox', { name: /replace pending/i });
            if (replacePending) await user.click(replacePending);
            await user.click(screen.getByRole('button', { name: 'Start assessment' }));
            await waitFor(() => expect(screen.getByText(/assessment queued/i)).toBeInTheDocument());
        };

        const firstView = render(modal());
        await launch();
        stream.send('operation', operation('running'));
        assessmentIds = ['first-ai-id'];
        stream.send('operation', operation('done', { assessment_ids: ['first-ai-id'] }));
        await waitFor(() => expect(vuln.assessments.map(a => a.id)).toContain('first-ai-id'));
        firstView.unmount();

        const secondView = render(modal());
        await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Assessment done.'));
        nextOperationId = 'op-2';
        await launch();
        stream.send('operation', { ...operation('running'), op_id: 'op-2', created_at: '2026-10-02T12:00:00Z' });
        await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Assessment running.'));
        const beforeSecond = fetchMock.mock.calls.filter(([url]) =>
            String(url).includes('/assessments') && !String(url).includes('/copilot-assessments')).length;
        assessmentIds = ['first-ai-id', 'second-ai-id'];
        const secondDone = { ...operation('done', { assessment_ids: ['second-ai-id'] }),
            op_id: 'op-2', created_at: '2026-10-02T12:00:00Z' };
        stream.send('operation', secondDone);
        await waitFor(() => expect(vuln.assessments.map(a => a.id)).toContain('second-ai-id'));
        await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Assessment done.'));
        await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) =>
            String(url).includes('/assessments') && !String(url).includes('/copilot-assessments'))).toHaveLength(beforeSecond + 2));
        const afterSecond = fetchMock.mock.calls.filter(([url]) =>
            String(url).includes('/assessments') && !String(url).includes('/copilot-assessments')).length;
        stream.send('operation', secondDone);
        expect(fetchMock.mock.calls.filter(([url]) =>
            String(url).includes('/assessments') && !String(url).includes('/copilot-assessments'))).toHaveLength(afterSecond);

        secondView.unmount();
        render(modal());
        await waitFor(() => expect(vuln.assessments.map(a => a.id)).toContain('second-ai-id'));
        await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Assessment done.'));
        restore();
    });
});

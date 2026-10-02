import { useState } from "react";
import type { Variant } from "../handlers/variant";
import CopilotAssessments from "../handlers/copilotAssessments";
import type { Target } from "../handlers/copilotAssessments";

export type Finding = { findingId: string; pkg: string; outdated: boolean };
export type PendingAssessment = { variant_ids?: string[]; variant_id?: string | null; targets?: { variant_id: string | null }[] };

type Props = {
    projectId: string;
    variantId?: string;
    vulnId: string;
    variants: Variant[];
    variantFindingsMap: Record<string, Finding[]>;
    pendingAssessments: PendingAssessment[];
    onStarted: (opId: string) => void;
    onClose: () => void;
};

export default function CopilotAssessmentPicker({
    projectId, variantId, vulnId, variants, variantFindingsMap, pendingAssessments, onStarted, onClose,
}: Readonly<Props>) {
    const choices = variants.filter(variant => (variantFindingsMap[variant.id]?.length ?? 0) > 0);
    const [selected, setSelected] = useState<string[]>(variantId ? [variantId] : []);
    const [packages, setPackages] = useState<Record<string, string>>({});
    const [acknowledged, setAcknowledged] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const targets: Target[] = choices
        .filter(variant => selected.includes(variant.id) && packages[variant.id])
        .map(variant => ({ variant_id: variant.id, package: packages[variant.id] }));
    const pendingVariants = choices.filter(variant => selected.includes(variant.id)
        && pendingAssessments.some(assessment => assessment.variant_ids?.includes(variant.id)
            || assessment.variant_id === variant.id
            || assessment.targets?.some(target => target.variant_id === variant.id)));
    const hasPending = pendingVariants.length > 0;

    const start = async () => {
        if (busy || targets.length !== selected.length || targets.length === 0 || (hasPending && !acknowledged)) return;
        setBusy(true);
        setError(null);
        try {
            const opId = await CopilotAssessments.start({
                project_id: projectId, vuln_id: vulnId, targets, replace_pending: hasPending && acknowledged,
            });
            onStarted(opId);
        } catch (cause) {
            setError(cause instanceof Error ? cause.message : "Could not start assessment");
        } finally {
            setBusy(false);
        }
    };

    return (
        <section aria-label="Copilot assessment picker" className="rounded-lg border border-sky-600 p-3 space-y-3">
            <h4 className="font-semibold">Assess with Copilot</h4>
            <p className="text-sm">Choose one observed package for each variant. Historical findings are available.
                Copilot will use this locally observed context; results remain pending human approval.</p>
            {choices.map(variant => (
                <div key={variant.id} className="flex flex-wrap items-center gap-3">
                    <label>
                        <input type="checkbox" checked={selected.includes(variant.id)}
                            onChange={event => {
                                setSelected(previous => event.target.checked
                                    ? [...previous, variant.id] : previous.filter(id => id !== variant.id));
                                setAcknowledged(false);
                            }} />
                        {" "}{variant.name}
                    </label>
                    {selected.includes(variant.id) && (
                        <label>Package for {variant.name}
                            <select value={packages[variant.id] ?? ""}
                                onChange={event => setPackages(previous => ({ ...previous, [variant.id]: event.target.value }))}>
                                <option value="">Select a package</option>
                                {[...new Set(variantFindingsMap[variant.id]?.map(f => f.pkg) ?? [])].map(pkg => (
                                    <option key={pkg} value={pkg}>{pkg}
                                        {variantFindingsMap[variant.id]?.find(f => f.pkg === pkg)?.outdated ? " (historical)" : ""}
                                    </option>
                                ))}
                            </select>
                        </label>
                    )}
                </div>
            ))}
            {hasPending && (
                <div role="status" className="text-amber-300">
                    <p>Existing pending AI assessments in {pendingVariants.map(v => v.name).join(", ")} will be replaced,
                        even when they cover another package in that variant.</p>
                    <label><input type="checkbox" checked={acknowledged}
                        onChange={event => setAcknowledged(event.target.checked)} /> Replace pending AI assessments</label>
                </div>
            )}
            {error && <p role="alert" className="text-red-300">{error}</p>}
            <button type="button" disabled={busy || !selected.length || targets.length !== selected.length || (hasPending && !acknowledged)}
                onClick={() => void start()}>Start assessment</button>
            <button type="button" onClick={onClose}>Cancel picker</button>
        </section>
    );
}

export type Target = { variant_id: string; package: string };

export type StartAssessmentRequest = {
    project_id: string;
    vuln_id: string;
    targets: Target[];
    replace_pending: boolean;
};

class CopilotAssessments {
    static async start(request: StartAssessmentRequest): Promise<string> {
        const response = await fetch(`${import.meta.env.VITE_API_URL}/api/copilot-assessments`, {
            method: "POST",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const detail = typeof data?.error === "string" ? data.error : `HTTP ${response.status}`;
            throw new Error(response.status === 409 ? `Conflict: ${detail}` : detail);
        }
        if (typeof data?.op_id !== "string") throw new Error("Assessment start returned no operation ID");
        return data.op_id;
    }
}

export default CopilotAssessments;

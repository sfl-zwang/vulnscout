export type CopilotStatus = {
    has_token: boolean;
    masked_token: string;
    model: string;
};

export type CopilotReadiness = {
    ready: boolean;
    errors: Record<string, string>;
    available_models: string[];
};

class CopilotSettings {
    private static readonly url = `${import.meta.env.VITE_API_URL}/api/config/copilot`;

    private static async request<T>(path: string, method = "GET", body?: object): Promise<T> {
        const response = await fetch(`${this.url}${path}`, {
            method,
            mode: "cors",
            ...(body ? { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(typeof data?.error === "string" ? data.error : `Copilot request failed (${response.status}).`);
        }
        return data as T;
    }

    private static status(data: CopilotStatus): CopilotStatus {
        return {
            has_token: data?.has_token === true,
            masked_token: typeof data?.masked_token === "string" ? data.masked_token : "",
            model: typeof data?.model === "string" ? data.model : "",
        };
    }

    static async get(): Promise<CopilotStatus> {
        return this.status(await this.request<CopilotStatus>(""));
    }

    static async set(value: { token?: string; model?: string }): Promise<CopilotStatus> {
        return this.status(await this.request<CopilotStatus>("", "PUT", value));
    }

    static async remove(): Promise<CopilotStatus> {
        return this.status(await this.request<CopilotStatus>("", "DELETE"));
    }

    static async check(): Promise<CopilotReadiness> {
        const data = await this.request<CopilotReadiness>("/check", "POST");
        return {
            ready: data?.ready === true,
            errors: data?.errors && typeof data.errors === "object" ? data.errors : {},
            available_models: Array.isArray(data?.available_models)
                ? data.available_models.filter((model): model is string => typeof model === "string") : [],
        };
    }
}

export default CopilotSettings;

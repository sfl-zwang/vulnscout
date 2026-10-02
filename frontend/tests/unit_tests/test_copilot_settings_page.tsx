import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";
import fetchMock from "jest-fetch-mock";
import Settings from "../../src/pages/Settings";
import CopilotSettings from "../../src/handlers/copilotSettings";
import Projects from "../../src/handlers/project";
import Variants from "../../src/handlers/variant";
import Config from "../../src/handlers/config";
import NvdApiKey from "../../src/handlers/nvdApiKey";

jest.mock("../../src/handlers/project", () => ({ __esModule: true, default: { list: jest.fn() } }));
jest.mock("../../src/handlers/variant", () => ({ __esModule: true, default: { list: jest.fn() } }));
jest.mock("../../src/handlers/config", () => ({ __esModule: true, default: { get: jest.fn() } }));
jest.mock("../../src/handlers/nvdApiKey", () => ({ __esModule: true, default: { get: jest.fn() } }));

fetchMock.enableMocks();
const status = { has_token: false, masked_token: "", model: "" };

describe("Copilot settings", () => {
  beforeEach(() => {
    fetchMock.resetMocks();
    (Projects.list as jest.Mock).mockResolvedValue([]);
    (Variants.list as jest.Mock).mockResolvedValue([]);
    (Config.get as jest.Mock).mockResolvedValue({
      project: null, variant: null, product_name: "", author_name: "vulnscout",
      client_name: "", contact_email: "", grype_memlimit: "",
    });
    (NvdApiKey.get as jest.Mock).mockResolvedValue({ has_key: false, masked_key: "" });
    fetchMock.mockResponse(async request => {
      if (request.url.endsWith("/api/config/copilot")) {
        return JSON.stringify(request.method === "GET" ? status : {
          has_token: true, masked_token: "********", model: "gpt-5",
        });
      }
      if (request.url.endsWith("/api/config/copilot/check")) {
        return JSON.stringify({ ready: true, errors: {}, available_models: ["gpt-5", "claude-sonnet-4"] });
      }
      return JSON.stringify({});
    });
  });

  test("saves token, clears password and shows only masked status", async () => {
    const user = userEvent.setup();
    render(<Settings />);
    await screen.findByLabelText("Copilot token");
    await user.type(screen.getByLabelText("Copilot token"), "github_pat_test");
    await user.click(screen.getByRole("button", { name: "Save Copilot token" }));
    await waitFor(() => expect(screen.getByLabelText("Copilot token")).toHaveValue(""));
    expect(screen.queryByText("github_pat_test")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("github_pat_test");
    expect(screen.getByText("********")).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url, options]) =>
      String(url).endsWith("/api/config/copilot") && options?.method === "PUT"
      && JSON.parse(String(options.body)).token === "github_pat_test")).toBe(true);
    expect(JSON.stringify(window.localStorage)).not.toContain("github_pat_test");
  });

  test("changes and removes an existing token", async () => {
    fetchMock.mockResponse(async request => {
      if (request.url.endsWith("/api/config/copilot")) {
        return JSON.stringify(request.method === "DELETE" ? status : {
          has_token: true, masked_token: "********", model: "gpt-5",
        });
      }
      return JSON.stringify({});
    });
    const user = userEvent.setup();
    render(<Settings />);
    const section = await screen.findByRole("region", { name: "Copilot" });
    expect(within(section).getByText("********")).toBeInTheDocument();
    await user.click(within(section).getByRole("button", { name: "Change" }));
    await user.type(within(section).getByLabelText("Copilot token"), "replacement");
    await user.click(within(section).getByRole("button", { name: "Cancel" }));
    expect(within(section).queryByDisplayValue("replacement")).not.toBeInTheDocument();
    await user.click(within(section).getByRole("button", { name: "Remove" }));
    await user.click(screen.getByRole("button", { name: "Remove token" }));
    await waitFor(() => expect(within(section).queryByText("********")).not.toBeInTheDocument());
    expect(fetchMock.mock.calls.some(([url, options]) =>
      String(url).endsWith("/api/config/copilot") && options?.method === "DELETE")).toBe(true);
  });

  test("clears models from a previous token on replacement and removal", async () => {
    let tokenPresent = true;
    fetchMock.mockResponse(async request => {
      if (request.url.endsWith("/api/config/copilot/check")) {
        return JSON.stringify({ ready: true, errors: {}, available_models: ["old-identity-model"] });
      }
      if (request.url.endsWith("/api/config/copilot")) {
        if (request.method === "DELETE") tokenPresent = false;
        return JSON.stringify({
          has_token: tokenPresent, masked_token: tokenPresent ? "********" : "", model: "",
        });
      }
      return JSON.stringify({});
    });
    const user = userEvent.setup();
    render(<Settings />);
    const section = await screen.findByRole("region", { name: "Copilot" });
    await user.click(within(section).getByRole("button", { name: "Check connection" }));
    expect(await within(section).findByRole("option", { name: "old-identity-model" })).toBeInTheDocument();
    await user.click(within(section).getByRole("button", { name: "Change" }));
    await user.type(within(section).getByLabelText("Copilot token"), "replacement");
    await user.click(within(section).getByRole("button", { name: "Save Copilot token" }));
    await waitFor(() => expect(within(section).queryByRole("option", { name: "old-identity-model" })).not.toBeInTheDocument());
    await user.click(within(section).getByRole("button", { name: "Check connection" }));
    expect(await within(section).findByRole("option", { name: "old-identity-model" })).toBeInTheDocument();
    await user.click(within(section).getByRole("button", { name: "Remove" }));
    await user.click(screen.getByRole("button", { name: "Remove token" }));
    await waitFor(() => expect(within(section).queryByRole("option", { name: "old-identity-model" })).not.toBeInTheDocument());
  });

  test("ignores an in-flight connection check after token replacement", async () => {
    let finishCheck: (value: string) => void = () => {};
    const waitingCheck = new Promise<string>(resolve => { finishCheck = resolve; });
    fetchMock.mockResponse(async request => {
      if (request.url.endsWith("/api/config/copilot/check")) return waitingCheck;
      if (request.url.endsWith("/api/config/copilot")) {
        return JSON.stringify({ has_token: true, masked_token: "********", model: "" });
      }
      return JSON.stringify({});
    });
    const user = userEvent.setup();
    render(<Settings />);
    const section = await screen.findByRole("region", { name: "Copilot" });
    await user.click(within(section).getByRole("button", { name: "Check connection" }));
    await user.click(within(section).getByRole("button", { name: "Change" }));
    await user.type(within(section).getByLabelText("Copilot token"), "replacement");
    await user.click(within(section).getByRole("button", { name: "Save Copilot token" }));
    await within(section).findByText("Copilot token saved.");
    finishCheck(JSON.stringify({ ready: true, errors: {}, available_models: ["old-identity-model"] }));
    await waitFor(() => expect(within(section).getByRole("button", { name: "Check connection" })).not.toBeDisabled());
    expect(within(section).queryByRole("option", { name: "old-identity-model" })).not.toBeInTheDocument();
  });

  test("selects the instance-wide model and reports an unavailable model", async () => {
    fetchMock.mockResponse(async request => {
      if (request.url.endsWith("/api/config/copilot")) {
        return JSON.stringify({ has_token: true, masked_token: "********", model: request.method === "GET" ? "" : "gpt-5" });
      }
      if (request.url.endsWith("/api/config/copilot/check")) {
        return JSON.stringify({ ready: true, errors: {}, available_models: ["gpt-5", "claude-sonnet-4"] });
      }
      return JSON.stringify({});
    });
    const user = userEvent.setup();
    render(<Settings />);
    const section = await screen.findByRole("region", { name: "Copilot" });
    await user.click(within(section).getByRole("button", { name: "Check connection" }));
    await within(section).findByRole("option", { name: "gpt-5" });
    await user.selectOptions(within(section).getByLabelText("Copilot model"), "gpt-5");
    await waitFor(() => expect(fetchMock.mock.calls.some(([url, options]) =>
      String(url).endsWith("/api/config/copilot") && options?.method === "PUT"
      && JSON.parse(String(options.body)).model === "gpt-5")).toBe(true));
    fetchMock.mockResponseOnce(JSON.stringify({ error: "Selected Copilot model is unavailable to this identity." }), { status: 400 });
    fireEvent.change(within(section).getByLabelText("Copilot model"), { target: { value: "claude-sonnet-4" } });
    expect(await within(section).findByText("Selected Copilot model is unavailable to this identity.")).toBeInTheDocument();
  });

  test("checks readiness without creating an assessment and scopes errors to Copilot", async () => {
    const user = userEvent.setup();
    render(<Settings />);
    const section = await screen.findByRole("region", { name: "Copilot" });
    await user.click(within(section).getByRole("button", { name: "Check connection" }));
    expect(await within(section).findByText("Copilot connection is ready.")).toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([, options]) => options?.method === "POST")
      .map(([url]) => String(url))).toEqual([expect.stringMatching(/\/api\/config\/copilot\/check$/)]);
    fetchMock.mockResponseOnce(JSON.stringify({
      ready: false, errors: { model: "Selected Copilot model is unavailable to this identity." },
      available_models: [],
    }));
    await user.click(within(section).getByRole("button", { name: "Check connection" }));
    expect(await within(section).findByText("Selected Copilot model is unavailable to this identity.")).toBeInTheDocument();
    expect(fetchMock.mock.calls.every(([url]) => !String(url).includes("/assessments"))).toBe(true);
  });

  test("typed client propagates server errors and does not return plaintext", async () => {
    fetchMock.resetMocks();
    fetchMock.mockResponseOnce(JSON.stringify({ error: "Invalid Copilot model ID." }), { status: 400 });
    await expect(CopilotSettings.set({ model: "invalid" })).rejects.toThrow("Invalid Copilot model ID.");
    fetchMock.mockResponseOnce(JSON.stringify({ has_token: true, masked_token: "********", model: "gpt-5" }));
    await expect(CopilotSettings.get()).resolves.toEqual({ has_token: true, masked_token: "********", model: "gpt-5" });
  });
});

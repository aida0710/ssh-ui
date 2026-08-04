import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RemoteKeyPanel } from "./RemoteKeyPanel";
import { ApiError } from "../api/client";
import type { RemoteKeyPlan, RemoteKeysApi } from "./api";

afterEach(() => {
  vi.restoreAllMocks();
});

const publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPr0nHGmQb99GXmUofxJM4BXGwGzO0jGsQFBspODbkvS deploy@laptop";
const fingerprint = "SHA256:bytFrSjxj2qRszG8sHhWN+YO3b9vDSU3gQtMorwKpEs";

const plan: RemoteKeyPlan = {
  alias: "bastion",
  user: "deploy",
  hostname: "bastion.example.com",
  port: "22",
  valuesFrom: "engine",
  fingerprint,
  keyPath: "~/.ssh/id_ed25519.pub",
  keyLine: publicKey,
  remotePath: "~/.ssh/authorized_keys",
  routine: "set -e\numask 077\ngrep -qxF \"$key\" \"$HOME/.ssh/authorized_keys\"\n",
  supported: true,
  manual: [
    "Open a session to the host yourself and check which shell the account uses.",
    "Append the public key line shown above to ~/.ssh/authorized_keys as a single line.",
  ],
  executableDirectives: [],
};

const proxyCommand = {
  keyword: "ProxyCommand",
  command: "/usr/bin/nc %h %p",
  path: "~/.ssh/config",
  line: 4,
  onEvaluate: false,
  onConnect: true,
  overridable: false,
};

function buildApi(overrides: Partial<RemoteKeysApi> = {}): RemoteKeysApi {
  return {
    plan: vi.fn().mockResolvedValue(plan),
    register: vi.fn().mockResolvedValue({ outcome: "added", exitCode: 0, stderr: "", truncated: false }),
    ...overrides,
  };
}

async function fillForm() {
  await userEvent.type(screen.getByLabelText("Host alias"), "bastion");
  await userEvent.type(screen.getByLabelText("Public key file"), "~/.ssh/id_ed25519.pub");
  await userEvent.type(screen.getByLabelText("Public key line"), publicKey);
}

async function fetchPlan(api: RemoteKeysApi) {
  render(<RemoteKeyPanel api={api} />);
  await fillForm();
  await userEvent.click(screen.getByRole("button", { name: "Show what this would do" }));
  return screen.findByRole("region", { name: "Confirm remote registration" });
}

describe("RemoteKeyPanel", () => {
  it("shows the alias, the effective user, the fingerprint and the change before any remote request", async () => {
    const api = buildApi();
    const confirmation = await fetchPlan(api);

    expect(within(confirmation).getByText("bastion")).toBeInTheDocument();
    expect(within(confirmation).getByText("deploy")).toBeInTheDocument();
    expect(within(confirmation).getByText("bastion.example.com:22")).toBeInTheDocument();
    expect(within(confirmation).getByText(fingerprint)).toBeInTheDocument();
    expect(within(confirmation).getByText(/Append one line to ~\/\.ssh\/authorized_keys/)).toBeInTheDocument();
    expect(within(confirmation).getByLabelText("Public key line to append")).toHaveTextContent(publicKey);
    expect(within(confirmation).getByLabelText("Remote command")).toHaveTextContent("umask 077");
    // Nothing on the remote host has been touched to produce this description.
    expect(api.register).not.toHaveBeenCalled();
  });

  it("keeps the confirm control unavailable until a plan has been fetched", async () => {
    const api = buildApi();
    render(<RemoteKeyPanel api={api} />);

    expect(screen.getByRole("button", { name: "Register the key" })).toBeDisabled();
    await fillForm();
    expect(screen.getByRole("button", { name: "Register the key" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Show what this would do" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Register the key" })).toBeEnabled());

    await userEvent.click(screen.getByRole("button", { name: "Register the key" }));
    await waitFor(() =>
      expect(api.register).toHaveBeenCalledWith({
        alias: "bastion",
        keyPath: "~/.ssh/id_ed25519.pub",
        publicKey,
        acknowledgeExecutable: false,
      }),
    );
    expect(await screen.findByText(/added/)).toBeInTheDocument();
  });

  it("withdraws the plan when the target changes, so the confirmation always matches", async () => {
    const api = buildApi();
    const confirmation = await fetchPlan(api);
    expect(confirmation).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Host alias"), "-two");

    expect(screen.queryByRole("region", { name: "Confirm remote registration" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Register the key" })).toBeDisabled();
    expect(api.register).not.toHaveBeenCalled();
  });

  it("offers manual instructions and no register control when the plan is unsupported", async () => {
    const api = buildApi({ plan: vi.fn().mockResolvedValue({ ...plan, supported: false }) });
    const confirmation = await fetchPlan(api);

    expect(within(confirmation).getByText(/Append the public key line shown above/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register the key" })).not.toBeInTheDocument();
  });

  it("falls back to manual instructions when the remote turns out to be unsupported", async () => {
    const api = buildApi({
      register: vi.fn().mockRejectedValue(
        new ApiError("unsupported_remote", 422, {
          code: "unsupported_remote",
          message: "this remote environment does not provide the POSIX shell this operation needs",
        }),
      ),
    });
    await fetchPlan(api);

    await userEvent.click(screen.getByRole("button", { name: "Register the key" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("unsupported_remote");
    expect(await screen.findByText(/Append the public key line shown above/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register the key" })).not.toBeInTheDocument();
  });

  it("will not register until an unavoidable executable directive is acknowledged", async () => {
    const api = buildApi({
      plan: vi.fn().mockResolvedValue({ ...plan, executableDirectives: [proxyCommand] }),
    });
    const confirmation = await fetchPlan(api);

    expect(within(confirmation).getByText("/usr/bin/nc %h %p")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Register the key" })).toBeDisabled();

    await userEvent.click(screen.getByLabelText(/accept that connecting runs it/));
    await userEvent.click(screen.getByRole("button", { name: "Register the key" }));

    await waitFor(() =>
      expect(api.register).toHaveBeenCalledWith({
        alias: "bastion",
        keyPath: "~/.ssh/id_ed25519.pub",
        publicKey,
        acknowledgeExecutable: true,
      }),
    );
  });

  it("surfaces the refusal code from the plan endpoint and never offers a confirmation", async () => {
    const api = buildApi({
      plan: vi.fn().mockRejectedValue(
        new ApiError("invalid_public_key", 400, {
          code: "invalid_public_key",
          message: "public key must be exactly one valid OpenSSH public key line",
        }),
      ),
    });
    render(<RemoteKeyPanel api={api} />);
    await fillForm();
    await userEvent.click(screen.getByRole("button", { name: "Show what this would do" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("invalid_public_key");
    expect(screen.queryByRole("region", { name: "Confirm remote registration" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Register the key" })).toBeDisabled();
  });

  it("surfaces the refusal code from the register endpoint and stores nothing", async () => {
    // React's test environment installs one flag of its own on the window; any
    // other new global would have come from the panel.
    const frameworkGlobals = ["IS_REACT_ACT_ENVIRONMENT"];
    const globalsBefore = Object.keys(window);
    const api = buildApi({
      register: vi.fn().mockRejectedValue(
        new ApiError("executable_directive_not_acknowledged", 409, {
          code: "executable_directive_not_acknowledged",
          message: "connecting would run a configured command that has not been acknowledged",
        }),
      ),
    });
    await fetchPlan(api);

    await userEvent.click(screen.getByRole("button", { name: "Register the key" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("executable_directive_not_acknowledged");
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    const added = Object.keys(window).filter(
      (key) => !globalsBefore.includes(key) && !frameworkGlobals.includes(key),
    );
    expect(added).toEqual([]);
  });

  it("adds no second status region to the shell", async () => {
    const api = buildApi();
    render(<RemoteKeyPanel api={api} />);

    expect(screen.queryAllByRole("status")).toHaveLength(0);
  });
});

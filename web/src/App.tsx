import { useEffect, useState } from "react";
import { apiClient, type HealthResponse } from "./api/client";
import type { SessionState } from "./session/bootstrap";

type AppProps = {
  bootstrap: () => Promise<SessionState>;
  health: () => Promise<HealthResponse>;
};

const sections = ["Connections", "Groups", "Config", "Keys", "Known Hosts", "History"];

export function App({ bootstrap, health }: AppProps) {
  const [state, setState] = useState<"starting" | "ready" | "error">("starting");
  const [version, setVersion] = useState("");

  useEffect(() => {
    let active = true;
    void bootstrap()
      .then((sessionState) => {
        if (!active) return null;
        apiClient.setCSRF(sessionState.csrfToken);
        return health();
      })
      .then((result) => {
        if (!active || result === null) return;
        setVersion(result.version);
        setState("ready");
      })
      .catch(() => {
        if (active) setState("error");
      });

    return () => {
      active = false;
      apiClient.clear();
    };
  }, [bootstrap, health]);

  if (state === "error") {
    return (
      <main>
        <h1>SSH UI</h1>
        <p role="alert">Secure local session could not be started. Restart ssh-ui and use the newly opened tab.</p>
      </main>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="border-b border-zinc-800 px-6 py-4">
        <h1 className="text-xl font-semibold">SSH UI</h1>
      </header>
      <div className="grid grid-cols-[15rem_1fr]">
        <nav aria-label="Primary" className="border-r border-zinc-800 p-4">
          <ul>
            {sections.map((section) => (
              <li key={section}>
                <button disabled className="w-full px-3 py-2 text-left text-zinc-500">{section}</button>
              </li>
            ))}
          </ul>
        </nav>
        <main className="p-8">
          <section aria-labelledby="status-heading" className="max-w-xl rounded-xl border border-zinc-800 bg-zinc-900 p-6">
            <h2 id="status-heading" className="font-medium">Local process</h2>
            <p role="status" className="mt-2 text-sm text-zinc-300">
              {state === "ready" ? `Local session active · ${version}` : "Starting secure local session…"}
            </p>
          </section>
        </main>
      </div>
    </div>
  );
}

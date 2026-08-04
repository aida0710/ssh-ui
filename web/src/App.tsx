import { useEffect, useState } from "react";
import { apiClient, type HealthResponse } from "./api/client";
import type { SessionState } from "./session/bootstrap";

type AppProps = {
  bootstrap: () => Promise<SessionState>;
  health: () => Promise<HealthResponse>;
};

const sections = ["Connections", "Config", "Groups", "Keys", "Known Hosts", "History"] as const;
type Section = (typeof sections)[number];
const enabledSections: Section[] = ["Connections", "Config", "Groups", "History"];

export function App({ bootstrap, health }: AppProps) {
  const [state, setState] = useState<"starting" | "ready" | "error">("starting");
  const [version, setVersion] = useState("");
  const [section, setSection] = useState<Section>("Connections");

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
      <header className="flex items-baseline gap-3 border-b border-zinc-800 px-6 py-4">
        <h1 className="text-xl font-semibold">SSH UI</h1>
        <p role="status" className="text-sm text-zinc-300">
          {state === "ready" ? `Local session active · ${version}` : "Starting secure local session…"}
        </p>
      </header>
      <div className="grid grid-cols-[15rem_1fr]">
        <nav aria-label="Primary" className="border-r border-zinc-800 p-4">
          <ul>
            {sections.map((name) => (
              <li key={name}>
                <button
                  type="button"
                  disabled={!enabledSections.includes(name)}
                  aria-current={section === name ? "page" : undefined}
                  onClick={() => setSection(name)}
                  className={`w-full px-3 py-2 text-left ${
                    enabledSections.includes(name) ? "text-zinc-200 hover:bg-zinc-900" : "text-zinc-500"
                  }`}
                >
                  {name}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        <main className="p-6">{state === "ready" ? <SectionView section={section} /> : null}</main>
      </div>
    </div>
  );
}

function SectionView({ section }: { section: Section }) {
  if (section === "Keys" || section === "Known Hosts") {
    return (
      <p className="text-sm text-zinc-400">{`${section} arrives with a later subsystem.`}</p>
    );
  }
  return (
    <section aria-labelledby="section-heading" className="flex flex-col gap-4">
      <h2 id="section-heading" className="font-medium">{section}</h2>
    </section>
  );
}

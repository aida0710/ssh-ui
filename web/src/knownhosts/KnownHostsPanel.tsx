import { useEffect, useState } from "react";
import {
  integrationsApi,
  type IntegrationsApi,
  type KnownHostCandidate,
  type KnownHostEntry,
  type KnownHostsResponse,
} from "../api/integrations";

type KnownHostsPanelProps = { api?: IntegrationsApi };

// Deleting a host key is destructive and scanning one contacts a host, so both
// are started deliberately: a deletion asks a second time before it is sent,
// and a scanned key is presented as a candidate rather than as a fact.
export function KnownHostsPanel({ api = integrationsApi }: KnownHostsPanelProps) {
  const [query, setQuery] = useState("");
  const [listing, setListing] = useState<KnownHostsResponse | null>(null);
  const [pending, setPending] = useState<KnownHostEntry | null>(null);
  const [scanHost, setScanHost] = useState("");
  const [notice, setNotice] = useState("");
  const [candidates, setCandidates] = useState<KnownHostCandidate[]>([]);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    void api
      .knownHosts("")
      .then((result) => {
        if (active) setListing(result);
      })
      .catch(() => {
        if (active) setError("The known_hosts file could not be read.");
      });
    return () => {
      active = false;
    };
  }, [api]);

  async function search(next: string) {
    setError("");
    try {
      setListing(await api.knownHosts(next));
    } catch {
      setError("The known_hosts file could not be read.");
    }
  }

  async function confirmDelete() {
    if (!pending || !listing) return;
    setError("");
    try {
      const result = await api.deleteKnownHosts(
        [{ line: pending.line, digest: pending.digest }],
        listing.path,
      );
      setStatus(`Removed one entry in transaction ${result.transactionId}.`);
      setPending(null);
      await search(query);
    } catch {
      setError("The entry could not be removed. Nothing was changed.");
      setPending(null);
    }
  }

  async function scan() {
    setError("");
    try {
      const result = await api.scanKnownHosts(scanHost, 22);
      setNotice(result.notice);
      setCandidates(result.candidates);
    } catch {
      setError("The host could not be scanned.");
    }
  }

  return (
    <section aria-labelledby="known-hosts-heading" className="flex flex-col gap-4">
      <h2 id="known-hosts-heading" className="font-medium">
        Known Hosts
      </h2>

      <p aria-live="polite" className="text-sm text-zinc-400">
        {status}
      </p>
      {error ? (
        <p role="alert" className="text-sm text-red-400">
          {error}
        </p>
      ) : null}

      <label className="flex flex-col gap-1 text-sm">
        <span>Search</span>
        <input
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            void search(event.target.value);
          }}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1"
        />
      </label>

      {listing ? (
        <table className="text-sm">
          <caption className="text-left text-zinc-400">{listing.path}</caption>
          <tbody>
            {listing.entries.map((item) => (
              <tr key={`${item.line}-${item.digest}`}>
                <td className="pr-3">{item.hashed ? "(hashed)" : item.hosts.join(", ")}</td>
                <td className="pr-3 text-zinc-400">{item.keyType}</td>
                <td className="pr-3 text-zinc-400">{item.fingerprint}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => setPending(item)}
                    className="rounded border border-zinc-700 px-2 py-1"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {pending ? (
        <div className="rounded border border-red-700 p-3 text-sm">
          <p>
            Remove line {pending.line} ({pending.fingerprint})? This is journalled and a backup is kept.
          </p>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              onClick={() => void confirmDelete()}
              className="rounded border border-red-600 px-3 py-1"
            >
              Confirm delete
            </button>
            <button
              type="button"
              onClick={() => setPending(null)}
              className="rounded border border-zinc-700 px-3 py-1"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1 text-sm">
          <span>Host to scan</span>
          <input
            value={scanHost}
            onChange={(event) => setScanHost(event.target.value)}
            className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1"
          />
        </label>
        <button type="button" onClick={() => void scan()} className="rounded border border-zinc-700 px-3 py-1 text-sm">
          Scan
        </button>
      </div>

      {notice ? <p className="text-sm text-amber-300">{notice}</p> : null}
      {candidates.length > 0 ? (
        <table className="text-sm">
          <caption className="text-left text-zinc-400">Scan candidates</caption>
          <tbody>
            {candidates.map((candidate) => (
              <tr key={`${candidate.host}-${candidate.fingerprint}`}>
                <td className="pr-3">{candidate.host}</td>
                <td className="pr-3 text-zinc-400">{candidate.keyType}</td>
                <td className="pr-3 text-zinc-400">{candidate.fingerprint}</td>
                <td className="text-amber-300">{candidate.verified ? "verified" : "unverified"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}

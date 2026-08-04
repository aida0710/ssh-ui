import { useEffect, useState } from "react";
import { failureCode } from "../api/client";
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
//
// Adding a candidate is the only way a scanned key becomes trusted, and it
// costs either a fingerprint the user obtained somewhere else or an explicit
// acknowledgement that they are trusting a key nobody verified.
export function KnownHostsPanel({ api = integrationsApi }: KnownHostsPanelProps) {
  const [query, setQuery] = useState("");
  const [listing, setListing] = useState<KnownHostsResponse | null>(null);
  const [pending, setPending] = useState<KnownHostEntry | null>(null);
  const [scanHost, setScanHost] = useState("");
  const [notice, setNotice] = useState("");
  const [candidates, setCandidates] = useState<KnownHostCandidate[]>([]);
  const [adding, setAdding] = useState<KnownHostCandidate | null>(null);
  const [expectedFingerprint, setExpectedFingerprint] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
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

  // The confirmation never inherits a proof or an acknowledgement. Both are
  // dropped when it closes and again when it opens, so what the user gave for
  // one key can never be spent on another.
  function resetAdd() {
    setExpectedFingerprint("");
    setAcknowledged(false);
  }

  function openAdd(candidate: KnownHostCandidate) {
    resetAdd();
    setAdding(candidate);
  }

  function closeAdd() {
    resetAdd();
    setAdding(null);
  }

  async function confirmAdd() {
    if (!adding) return;
    const typed = expectedFingerprint.trim();
    // A typed fingerprint is a claim about this key. If it disagrees with the
    // key that was scanned the user is looking at a different key than the one
    // they were told about, which is shown rather than sent to the server.
    if (typed !== "" && typed !== adding.fingerprint) {
      setError(
        `The fingerprint you typed does not match this key. You typed ${typed}; ` +
          `the scan returned ${adding.fingerprint}. Nothing was added.`,
      );
      return;
    }
    setError("");
    try {
      const result = await api.addKnownHost(
        { host: adding.host, port: adding.port, keyType: adding.keyType, key: adding.key },
        typed,
        acknowledged,
      );
      setStatus(`Added ${adding.host} in transaction ${result.transactionId}.`);
      closeAdd();
      await search(query);
    } catch (failure) {
      const code = failureCode(failure);
      setError(
        code === ""
          ? "The key could not be added. Nothing was changed."
          : `The key could not be added (${code}). Nothing was changed.`,
      );
      closeAdd();
    }
  }

  const provenOrAcknowledged = expectedFingerprint.trim() !== "" || acknowledged;

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
                {/* A scan cannot establish identity, so the label describes how
                    the key was obtained and never repeats a claim of the
                    response. */}
                <td className="pr-3 text-amber-300">unverified</td>
                <td>
                  <button
                    type="button"
                    onClick={() => openAdd(candidate)}
                    className="rounded border border-zinc-700 px-2 py-1"
                  >
                    Add
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {adding ? (
        <div className="rounded border border-amber-700 p-3 text-sm">
          <h3 className="font-medium text-amber-300">Add an unverified host key</h3>
          <p className="text-zinc-300">
            ssh-keyscan returned this key from {adding.host}. Anything answering at that address could have
            sent it, so ssh-ui will not treat it as this host&apos;s key on its own. Type the fingerprint you
            obtained through another channel, or acknowledge that you are trusting a key nobody verified.
          </p>
          <p className="text-zinc-400">
            {adding.keyType} · {adding.fingerprint}
          </p>
          <label className="mt-2 flex flex-col gap-1">
            <span>Fingerprint you obtained through another channel</span>
            <input
              value={expectedFingerprint}
              onChange={(event) => setExpectedFingerprint(event.target.value)}
              className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1"
            />
          </label>
          <label className="mt-2 flex items-center gap-2">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
            />
            <span>I could not verify this key and I accept the risk of trusting it</span>
          </label>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              disabled={!provenOrAcknowledged}
              onClick={() => void confirmAdd()}
              className="rounded border border-amber-600 px-3 py-1 disabled:border-zinc-800 disabled:text-zinc-600"
            >
              Add to known_hosts
            </button>
            <button type="button" onClick={closeAdd} className="rounded border border-zinc-700 px-3 py-1">
              Cancel
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}

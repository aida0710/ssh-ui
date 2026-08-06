import { useEffect, useState } from "react";
import { useTranslate } from "../i18n/context";
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
  const t = useTranslate();
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
        if (active) setError(t("kh.unreadable"));
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
      setError(t("kh.unreadable"));
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
      setStatus(t("kh.removed", { id: result.transactionId }));
      setPending(null);
      await search(query);
    } catch {
      setError(t("kh.removeFailed"));
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
      setError(t("kh.scanFailed"));
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
      setError(t("kh.fingerprintMismatch", { typed, scanned: adding.fingerprint }));
      return;
    }
    setError("");
    try {
      const result = await api.addKnownHost(
        { host: adding.host, port: adding.port, keyType: adding.keyType, key: adding.key },
        typed,
        acknowledged,
      );
      setStatus(t("kh.added", { host: adding.host, id: result.transactionId }));
      closeAdd();
      await search(query);
    } catch (failure) {
      const code = failureCode(failure);
      setError(
        code === ""
          ? t("kh.addFailed")
          : t("kh.addFailedCode", { code }),
      );
      closeAdd();
    }
  }

  const provenOrAcknowledged = expectedFingerprint.trim() !== "" || acknowledged;

  return (
    <section aria-labelledby="known-hosts-heading" className="flex flex-col gap-4">
      <h2 id="known-hosts-heading" className="font-medium">
        {t("kh.heading")}
      </h2>

      <p aria-live="polite" className="text-sm text-ink-muted">
        {status}
      </p>
      {error ? (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}

      {/*
        Scanning is what a user comes here to do; reading the file is how they
        check the result. The control sat below the whole listing, so reaching
        it meant scrolling past every host already known. Its results travel
        with it: leaving them behind would have put the candidate list below the
        file the user was scanning in order to add to.
      */}
      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1 text-sm">
          <span>{t("kh.hostToScan")}</span>
          <input
            value={scanHost}
            onChange={(event) => setScanHost(event.target.value)}
            className="rounded border border-control-line bg-control px-2 py-1"
          />
        </label>
        <button type="button" onClick={() => void scan()} className="rounded border border-control-line px-3 py-1 text-sm">
          {t("kh.scan")}
        </button>
      </div>

      {notice ? <p className="text-sm text-notice-ink">{notice}</p> : null}
      {candidates.length > 0 ? (
        <table className="text-sm">
          <caption className="text-left text-ink-muted">{t("kh.scanCandidates")}</caption>
          <tbody>
            {candidates.map((candidate) => (
              <tr key={`${candidate.host}-${candidate.fingerprint}`}>
                <td className="pr-3">{candidate.host}</td>
                <td className="pr-3 text-ink-muted">{candidate.keyType}</td>
                <td className="pr-3 text-ink-muted">{candidate.fingerprint}</td>
                {/* A scan cannot establish identity, so the label describes how
                    the key was obtained and never repeats a claim of the
                    response. */}
                <td className="pr-3 text-notice-ink">{t("kh.unverified")}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => openAdd(candidate)}
                    className="rounded border border-control-line px-2 py-1"
                  >
                    {t("kh.add")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {adding ? (
        <div className="rounded border border-notice-line p-3 text-sm">
          <h3 className="font-medium text-notice-ink">{t("kh.addHeading")}</h3>
          <p className="text-ink-muted">{t("kh.addExplain", { host: adding.host })}</p>
          <p className="text-ink-muted">
            {adding.keyType} · {adding.fingerprint}
          </p>
          <label className="mt-2 flex flex-col gap-1">
            <span>{t("kh.expectedFingerprint")}</span>
            <input
              value={expectedFingerprint}
              onChange={(event) => setExpectedFingerprint(event.target.value)}
              className="rounded border border-control-line bg-control px-2 py-1"
            />
          </label>
          <label className="mt-2 flex items-center gap-2">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
            />
            <span>{t("kh.acknowledge")}</span>
          </label>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              disabled={!provenOrAcknowledged}
              onClick={() => void confirmAdd()}
              className="rounded border border-notice-line px-3 py-1 disabled:border-line disabled:text-ink-faint"
            >
              {t("kh.addToKnownHosts")}
            </button>
            <button type="button" onClick={closeAdd} className="rounded border border-control-line px-3 py-1">
              {t("kh.cancel")}
            </button>
          </div>
        </div>
      ) : null}
      <label className="flex flex-col gap-1 text-sm">
        <span>{t("kh.search")}</span>
        <input
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            void search(event.target.value);
          }}
          className="rounded border border-control-line bg-control px-2 py-1"
        />
      </label>

      {listing ? (
        <table className="text-sm">
          <caption className="text-left text-ink-muted">{listing.path}</caption>
          <tbody>
            {listing.entries.map((item) => (
              <tr key={`${item.line}-${item.digest}`}>
                <td className="pr-3">{item.hashed ? t("kh.hashed") : item.hosts.join(", ")}</td>
                <td className="pr-3 text-ink-muted">{item.keyType}</td>
                <td className="pr-3 text-ink-muted">{item.fingerprint}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => setPending(item)}
                    className="rounded border border-control-line px-2 py-1"
                  >
                    {t("kh.delete")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {pending ? (
        <div className="rounded border border-control-line p-3 text-sm">
          <p>
            {t("kh.confirmRemove", { line: pending.line, fingerprint: pending.fingerprint })}
          </p>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              onClick={() => void confirmDelete()}
              className="rounded border border-control-line px-3 py-1"
            >
              {t("kh.confirmDelete")}
            </button>
            <button
              type="button"
              onClick={() => setPending(null)}
              className="rounded border border-control-line px-3 py-1"
            >
              {t("kh.cancel")}
            </button>
          </div>
        </div>
      ) : null}

    </section>
  );
}

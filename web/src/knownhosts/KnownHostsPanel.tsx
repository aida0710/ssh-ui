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
import {
  CheckboxField,
  Field,
  control,
  secondaryAction,
  sectionCard,
  sectionHeading,
  tableHeadCell,
  tableHeadRow,
} from "../ui/form";
import { Notice } from "../ui/surface";
import { MetricCard, MetricGrid, PageHeader } from "../ui/page";

type KnownHostsPanelProps = { api?: IntegrationsApi };

// ホスト鍵の削除は破壊的で、スキャンはホストに接続するので、
// どちらも意図的に始める: 削除は送信前にもう一度尋ね、
// スキャンした鍵は事実としてではなく候補として提示する。
//
// スキャンした鍵が信頼される唯一の方法は候補を追加することであり、
// それにはユーザーが他所で入手したフィンガープリント、または誰も
// 検証していない鍵を信頼するという明示的な了承のどちらかが要る。
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

  // 確認は証拠や了承を決して引き継がない。どちらも閉じるときと
  // 開くときの両方で捨てられるので、ある鍵のために与えたものが
  // 別の鍵に使われることは決してない。
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
    // 入力されたフィンガープリントは、この鍵についての主張だ。もし
    // スキャンされた鍵と食い違えば、ユーザーは説明された鍵とは別の鍵を
    // 見ていることになる。それはサーバーに送るのではなく画面に表示する。
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
    <section aria-label={t("kh.heading")} className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <PageHeader title={t("kh.heading")} description={t("kh.pageDescription")} />
      <MetricGrid>
        <MetricCard label={t("kh.metricEntries")} value={listing?.entries.length ?? 0} />
        <MetricCard
          label={t("kh.metricHashed")}
          value={listing?.entries.filter((entry) => entry.hashed).length ?? 0}
        />
        <MetricCard
          label={t("kh.metricCandidates")}
          value={candidates.length}
          attention={candidates.length > 0}
        />
      </MetricGrid>

      <p aria-live="polite" className="text-sm text-ink-muted">
        {status}
      </p>
      {error ? (
        <Notice tone="danger">{error}</Notice>
      ) : null}

      {/*
        スキャンはユーザーがここに来て行うことであり、ファイルを読むのは
        結果を確認する方法だ。コントロールは一覧全体の下にあったので、
        そこに到達するには既知のホストすべてを越えてスクロールする必要があった。
        結果はそれと共に移動する: 元の位置に残していたら、候補リストは
        ユーザーが追加しようとスキャンしているファイルより下に置かれてしまっていた。
      */}
      <section className={sectionCard} aria-labelledby="known-hosts-scan-heading">
        <h3 id="known-hosts-scan-heading" className={sectionHeading}>
          {t("kh.scanHeading")}
        </h3>
        <div className="flex flex-wrap items-end gap-2">
          <Field label={t("kh.hostToScan")}>
            <input
              value={scanHost}
              onChange={(event) => setScanHost(event.target.value)}
              className={control}
            />
          </Field>
          <button type="button" onClick={() => void scan()} className={secondaryAction}>
            {t("kh.scan")}
          </button>
        </div>

        {notice ? <p className="text-sm text-notice-ink">{notice}</p> : null}
        {candidates.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <caption className="mb-2 text-left text-ink-muted">{t("kh.scanCandidates")}</caption>
              <thead>
                <tr className={tableHeadRow}>
                  <th scope="col" className={tableHeadCell}>{t("kh.columnHost")}</th>
                  <th scope="col" className={tableHeadCell}>{t("kh.columnType")}</th>
                  <th scope="col" className={tableHeadCell}>{t("kh.columnFingerprint")}</th>
                  <th scope="col" className={tableHeadCell}>{t("kh.columnTrust")}</th>
                  <th scope="col" className={tableHeadCell}>{t("kh.columnActions")}</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((candidate) => (
                  <tr key={`${candidate.host}-${candidate.fingerprint}`} className="border-b border-line last:border-b-0">
                    <td className="py-2 pr-3">{candidate.host}</td>
                    <td className="py-2 pr-3 text-ink-muted">{candidate.keyType}</td>
                    <td className="py-2 pr-3 font-mono text-xs text-ink-muted">{candidate.fingerprint}</td>
                    {/* スキャンでは identity を確立できないので、ラベルは鍵をどう
                        取得したかを説明し、応答の
                        主張を繰り返すことは決してない。 */}
                    <td className="py-2 pr-3 text-notice-ink">{t("kh.unverified")}</td>
                    <td className="py-2">
                      <button
                        type="button"
                        onClick={() => openAdd(candidate)}
                        className={secondaryAction}
                      >
                        {t("kh.add")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}

        {adding ? (
          <div className="rounded border border-notice-line p-3 text-sm">
            <h3 className="font-medium text-notice-ink">{t("kh.addHeading")}</h3>
            <p className="text-ink-muted">{t("kh.addExplain", { host: adding.host })}</p>
            <p className="text-ink-muted">
              {adding.keyType} · {adding.fingerprint}
            </p>
            <Field label={t("kh.expectedFingerprint")}>
              <input
                value={expectedFingerprint}
                onChange={(event) => setExpectedFingerprint(event.target.value)}
                className={control}
              />
            </Field>
            <CheckboxField
              label={t("kh.acknowledge")}
              checked={acknowledged}
              onChange={setAcknowledged}
            />
            <div className="mt-2 flex gap-2">
              <button
                type="button"
                disabled={!provenOrAcknowledged}
                onClick={() => void confirmAdd()}
                className="rounded border border-notice-line px-3 py-1 disabled:border-line disabled:text-ink-faint"
              >
                {t("kh.addToKnownHosts")}
              </button>
              <button type="button" onClick={closeAdd} className={secondaryAction}>
                {t("kh.cancel")}
              </button>
            </div>
          </div>
        ) : null}
      </section>

      <section className={sectionCard} aria-labelledby="known-hosts-trusted-heading">
        <h3 id="known-hosts-trusted-heading" className={sectionHeading}>
          {t("kh.trustedHeading")}
        </h3>
        <Field label={t("kh.search")}>
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              void search(event.target.value);
            }}
            className={control}
          />
        </Field>

        {listing ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <caption className="mb-2 text-left text-ink-muted">{listing.path}</caption>
              <thead>
                <tr className={tableHeadRow}>
                  <th scope="col" className={tableHeadCell}>{t("kh.columnHost")}</th>
                  <th scope="col" className={tableHeadCell}>{t("kh.columnType")}</th>
                  <th scope="col" className={tableHeadCell}>{t("kh.columnFingerprint")}</th>
                  <th scope="col" className={tableHeadCell}>{t("kh.columnActions")}</th>
                </tr>
              </thead>
              <tbody>
                {listing.entries.map((item) => (
                  <tr key={`${item.line}-${item.digest}`} className="border-b border-line last:border-b-0">
                    <td className="py-2 pr-3">{item.hashed ? t("kh.hashed") : item.hosts.join(", ")}</td>
                    <td className="py-2 pr-3 text-ink-muted">{item.keyType}</td>
                    <td className="py-2 pr-3 font-mono text-xs text-ink-muted">{item.fingerprint}</td>
                    <td className="py-2">
                      <button
                        type="button"
                        onClick={() => setPending(item)}
                        className={secondaryAction}
                      >
                        {t("kh.delete")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
                className={secondaryAction}
              >
                {t("kh.confirmDelete")}
              </button>
              <button
                type="button"
                onClick={() => setPending(null)}
                className={secondaryAction}
              >
                {t("kh.cancel")}
              </button>
            </div>
          </div>
        ) : null}
      </section>
    </section>
  );
}

import { useCallback, useEffect, useState } from "react";
import { RevealDialog } from "./RevealDialog";
import { CopyButton } from "../ui/CopyButton";
import { useTranslate, type Translate } from "../i18n/context";
import type { MessageKey } from "../i18n/messages";
import {
  keysApi,
  type KeyCertificate,
  type KeyInventoryResponse,
  type KeyItem,
  type KeysApi,
  type KeyVariant,
  type TrashListResponse,
} from "./api";

type KeysScreenProps = { api?: KeysApi };

type ScreenState = "loading" | "ready" | "error";

// certificateLines describes an OpenSSH certificate in the terms that decide
// whether it is usable: who it names, who it is for, and whether it has run
// out. An expired certificate that only says "certificate" is indistinguishable
// from a working one, which is the whole reason design §6.3 classifies them.
function certificateLines(
  certificate: KeyCertificate,
  now: number,
  t: Translate,
): { text: string; expired: boolean }[] {
  const lines: { text: string; expired: boolean }[] = [];
  if (certificate.keyId !== "") lines.push({ text: t("keys.certKeyId", { keyId: certificate.keyId }), expired: false });
  if (certificate.principals.length > 0) {
    lines.push({ text: t("keys.certFor", { principals: certificate.principals.join(", ") }), expired: false });
  } else {
    // A certificate with no principal is valid for every user on the host that
    // trusts its CA. That is a fact about its reach, not a missing field.
    lines.push({ text: t("keys.certAnyPrincipal"), expired: false });
  }
  if (certificate.neverExpires) {
    lines.push({ text: t("keys.certNeverExpires"), expired: false });
  } else {
    const expiry = new Date(certificate.validBefore * 1000);
    const expired = certificate.validBefore * 1000 <= now;
    const when = `${expiry.toISOString().slice(0, 16).replace("T", " ")}Z`;
    lines.push({ text: expired ? t("keys.certExpired", { when }) : t("keys.certValidUntil", { when }), expired });
  }
  if (certificate.signedKeyType !== "") {
    lines.push({
      text: t("keys.certSigns", {
        keyType: certificate.signedKeyType,
        fingerprint: certificate.signedKeyFingerprint,
      }).trim(),
      expired: false,
    });
  }
  return lines;
}

const noteLabels: Record<string, MessageKey> = {
  fingerprint_unavailable: "keys.noteFingerprintUnavailable",
  symbolic_link: "keys.noteSymbolicLink",
  empty_file: "keys.noteEmptyFile",
  not_regular_file: "keys.noteNotRegularFile",
  comment_not_preserved: "keys.noteCommentNotPreserved",
};

export function KeysScreen({ api = keysApi }: KeysScreenProps) {
  const t = useTranslate();
  const [state, setState] = useState<ScreenState>("loading");
  const [inventory, setInventory] = useState<KeyInventoryResponse | null>(null);
  const [trash, setTrash] = useState<TrashListResponse | null>(null);
  const [variants, setVariants] = useState<KeyVariant[]>([]);
  const [algorithm, setAlgorithm] = useState("ed25519");
  const [fileName, setFileName] = useState("");
  const [comment, setComment] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [unencrypted, setUnencrypted] = useState(false);
  const [terminalCommand, setTerminalCommand] = useState<string[] | null>(null);
  const [revealing, setRevealing] = useState<KeyItem | null>(null);
  const [changingPassphrase, setChangingPassphrase] = useState<KeyItem | null>(null);
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [removePassphrase, setRemovePassphrase] = useState(false);
  const [registering, setRegistering] = useState<KeyItem | null>(null);
  const [agentPassphrase, setAgentPassphrase] = useState("");
  const [agentLifetime, setAgentLifetime] = useState(0);
  const [storeInKeychain, setStoreInKeychain] = useState(false);
  const [publicKeyView, setPublicKeyView] = useState<{ relativePath: string; text: string } | null>(null);
  const [pendingPurge, setPendingPurge] = useState("");
  const [failure, setFailure] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [nextInventory, nextTrash, nextAlgorithms] = await Promise.all([
        api.inventory(),
        api.listTrash(),
        api.algorithms(),
      ]);
      setInventory(nextInventory);
      setTrash(nextTrash);
      setVariants(nextAlgorithms.variants);
      setState("ready");
    } catch {
      setState("error");
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const selected = variants.find((variant) => variant.algorithm === algorithm);
  const inProcess = selected === undefined || selected.inProcess;
  // Read at render, so a certificate that runs out while this screen is open
  // stops being described as valid the next time anything refreshes it.
  const now = Date.now();

  async function submitGeneration() {
    setFailure("");
    setTerminalCommand(null);
    try {
      if (selected !== undefined && !selected.inProcess) {
        const response = await api.hardwareCommand({ algorithm, fileName, comment });
        setTerminalCommand(response.command);
        return;
      }
      await api.generate({
        algorithm,
        bits: selected?.bits ?? 0,
        fileName,
        comment,
        passphrase,
        unencrypted,
      });
      setPassphrase("");
      setFileName("");
      await refresh();
    } catch {
      setPassphrase("");
      setFailure(t("keys.createFailed"));
    }
  }

  function closePassphraseForm() {
    setCurrentPassphrase("");
    setNewPassphrase("");
    setRemovePassphrase(false);
    setChangingPassphrase(null);
  }

  // The passphrase lives in component state for the duration of one submit and
  // is cleared on success and on failure. It is never stored anywhere else.
  async function submitPassphrase(item: KeyItem) {
    setFailure("");
    try {
      await api.changePassphrase(item.id, {
        currentPassphrase,
        newPassphrase: removePassphrase ? "" : newPassphrase,
        unencrypted: removePassphrase,
      });
      closePassphraseForm();
      await refresh();
    } catch {
      setCurrentPassphrase("");
      setNewPassphrase("");
      setFailure(t("keys.passphraseFailed"));
    }
  }

  function closeAgentForm() {
    setAgentPassphrase("");
    setAgentLifetime(0);
    setStoreInKeychain(false);
    setRegistering(null);
  }

  // Registration holds the passphrase exactly as long as the change-passphrase
  // form does: for one submit, cleared on success and on failure alike. The
  // reply is deliberately discarded — refresh re-reads the inventory, so what
  // the screen shows afterwards is what the agent reports it holds, not what
  // this request claimed it would.
  async function submitRegistration(item: KeyItem) {
    setFailure("");
    try {
      await api.registerWithAgent(item.id, {
        passphrase: agentPassphrase,
        lifetimeSeconds: agentLifetime,
        storeInKeychain,
      });
      closeAgentForm();
      await refresh();
    } catch {
      setAgentPassphrase("");
      setFailure(t("keys.agentFailed"));
    }
  }

  // A public key is not a secret, so this is an ordinary read with no
  // confirmation and no audit note. It is shown before it is copied for the
  // same reason every other value on this screen is: what goes on the
  // clipboard should be the thing the user is looking at.
  async function showPublicKey(item: KeyItem) {
    setFailure("");
    try {
      const response = await api.publicKey(item.id);
      setPublicKeyView({ relativePath: response.relativePath, text: response.publicKey.trimEnd() });
    } catch {
      setPublicKeyView(null);
      setFailure(t("keys.publicKeyFailed"));
    }
  }

  async function moveToTrash(keyId: string) {
    setFailure("");
    try {
      await api.trash(keyId);
      await refresh();
    } catch {
      setFailure(t("keys.trashFailed"));
    }
  }

  async function restore(entryId: string) {
    setFailure("");
    try {
      const response = await api.restore(entryId);
      if (response.blockers.length > 0) {
        setFailure(t("keys.restoreRefused", { blockers: response.blockers.join(", ") }));
        return;
      }
      await refresh();
    } catch {
      setFailure(t("keys.restoreFailed"));
    }
  }

  async function purge(entryId: string) {
    setFailure("");
    try {
      await api.purge(entryId);
      setPendingPurge("");
      await refresh();
    } catch {
      setFailure(t("keys.purgeFailed"));
    }
  }

  if (state === "loading") {
    return <p aria-live="polite">{t("keys.reading")}</p>;
  }
  if (state === "error" || inventory === null || trash === null) {
    return <p role="alert">{t("keys.unreadable")}</p>;
  }

  return (
    <section aria-labelledby="keys-heading" className="flex flex-col gap-8">
      <h2 id="keys-heading" className="text-lg font-medium">
        {t("keys.heading")}
      </h2>
      {failure !== "" && (
        <p role="alert" className="rounded-md border border-red-800 p-3 text-sm text-red-300">
          {failure}
        </p>
      )}

      <table className="w-full text-left text-sm">
        <caption className="sr-only">{t("keys.tableCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("keys.colFile")}</th>
            <th scope="col">{t("keys.colKind")}</th>
            <th scope="col">{t("keys.colAlgorithm")}</th>
            <th scope="col">{t("keys.colFingerprint")}</th>
            <th scope="col">{t("keys.colPermissions")}</th>
            <th scope="col">{t("keys.colUsedBy")}</th>
            <th scope="col">{t("keys.colActions")}</th>
          </tr>
        </thead>
        <tbody>
          {inventory.items.map((item) => (
            <tr key={item.id}>
              <td>{item.relativePath}</td>
              <td>
                {item.kind}
                {item.certificate === undefined ? null : (
                  <ul className="text-xs text-zinc-400">
                    {certificateLines(item.certificate, now, t).map((line) => (
                      <li key={line.text} className={line.expired ? "text-red-300" : undefined}>
                        {line.text}
                      </li>
                    ))}
                  </ul>
                )}
              </td>
              <td>{item.bits > 0 ? `${item.algorithm} · ${item.bits}` : item.algorithm}</td>
              <td>
                {item.fingerprint !== "" ? item.fingerprint : null}
                {item.notes.map((note) => (
                  <span key={note} className="ml-2 text-amber-300">
                    {note in noteLabels ? t(noteLabels[note]!) : note}
                  </span>
                ))}
              </td>
              <td>
                {item.permission}
                {item.permissionRisk && <span className="ml-2 text-red-300">{t("keys.permissionRisk")}</span>}
              </td>
              <td>{item.references.map((reference) => reference.hostPatterns.join(" ")).join(", ")}</td>
              <td>
                {(item.kind === "public_key" || item.kind === "certificate") && (
                  <button type="button" onClick={() => void showPublicKey(item)}>
                    {t("keys.showPublicKey")}
                  </button>
                )}
                {item.kind === "private_key" && (
                  <>
                    <button type="button" onClick={() => setRevealing(item)}>
                      {t("keys.showPrivateKey")}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        closePassphraseForm();
                        closeAgentForm();
                        setChangingPassphrase(item);
                      }}
                    >
                      {t("keys.changePassphrase")}
                    </button>
                    <button
                      type="button"
                      disabled={!inventory.agentAvailable}
                      onClick={() => {
                        closePassphraseForm();
                        closeAgentForm();
                        setRegistering(item);
                      }}
                    >
                      {t("keys.addToAgent")}
                    </button>
                    <button type="button" onClick={() => void moveToTrash(item.id)}>
                      {t("keys.moveToTrash")}
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {publicKeyView !== null && (
        <section aria-labelledby="public-key-heading" className="flex flex-col gap-2 rounded-xl border border-zinc-800 p-4">
          <h3 id="public-key-heading" className="font-medium">
            {t("keys.publicKeyHeading", { path: publicKeyView.relativePath })}
          </h3>
          <pre aria-label={t("keys.publicKeyLabel")} className="overflow-x-auto rounded-md bg-zinc-950 p-4 text-xs">
            {publicKeyView.text}
          </pre>
          <div className="flex gap-2">
            <CopyButton value={publicKeyView.text} label="copy.publicKey" />
            <button type="button" onClick={() => setPublicKeyView(null)}>
              {t("keys.close")}
            </button>
          </div>
        </section>
      )}

      {/*
        A file the scanner refused to interpret used to be simply absent from
        the table, which made an incomplete inventory look like a complete one.
        Design §6.3 classifies everything under ~/.ssh; these are the entries it
        could not, and saying so is the difference between "there is nothing
        else here" and "there is something here I could not read".
      */}
      {inventory.unreadable.length > 0 && (
        <section aria-labelledby="unreadable-heading" className="flex flex-col gap-2">
          <h3 id="unreadable-heading" className="font-medium text-amber-300">
            {t("keys.unreadableHeading")}
          </h3>
          <p className="text-sm text-zinc-400">{t("keys.unreadableNote")}</p>
          <ul className="text-sm text-zinc-300">
            {inventory.unreadable.map((file) => (
              <li key={file.relativePath}>{t("keys.unreadableEntry", { path: file.relativePath, reason: file.reason })}</li>
            ))}
          </ul>
        </section>
      )}

      {inventory.unresolvedReferences.length > 0 && (
        <section aria-labelledby="unresolved-heading" className="flex flex-col gap-2">
          <h3 id="unresolved-heading" className="font-medium text-amber-300">
            {t("keys.unresolvedHeading")}
          </h3>
          <ul className="text-sm text-zinc-300">
            {inventory.unresolvedReferences.map((reference) => (
              <li key={`${reference.configPath}:${reference.line}:${reference.value}`}>
                {t("keys.referenceWithReason", {
                  directive: reference.directive,
                  value: reference.value,
                  path: reference.configPath,
                  line: reference.line,
                  reason: reference.reason,
                })}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby="agent-heading" className="flex flex-col gap-2">
        <h3 id="agent-heading" className="font-medium">
          {t("keys.agentHeading")}
        </h3>
        {inventory.agentAvailable ? (
          inventory.agentIdentities.length === 0 ? (
            <p className="text-sm text-zinc-400">{t("keys.agentEmpty")}</p>
          ) : (
            <table className="w-full text-left text-sm">
              <caption className="sr-only">{t("keys.agentIdentitiesCaption")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("keys.colAlgorithm")}</th>
                  <th scope="col">{t("keys.colFingerprint")}</th>
                  <th scope="col">{t("keys.colComment")}</th>
                </tr>
              </thead>
              <tbody>
                {inventory.agentIdentities.map((identity) => (
                  <tr key={identity.fingerprint}>
                    <td>{identity.bits > 0 ? `${identity.algorithm} · ${identity.bits}` : identity.algorithm}</td>
                    <td>{identity.fingerprint}</td>
                    <td>{identity.comment}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : (
          // ssh-add talks to whatever SSH_AUTH_SOCK names. Saying "no agent is
          // running" would be a guess: this process may simply not have been
          // given the socket. The message says what is missing, not why.
          <p className="text-sm text-amber-300">
            {t("keys.agentUnavailable")}
          </p>
        )}
        {inventory.agentDelegations.length > 0 && (
          <>
            <p className="text-sm text-zinc-400">
              {t("keys.agentDelegationsNote")}
            </p>
            <ul className="text-sm text-zinc-300">
              {inventory.agentDelegations.map((reference) => (
                <li key={`${reference.configPath}:${reference.line}`}>
                  {t("keys.reference", {
                    directive: reference.directive,
                    value: reference.value,
                    path: reference.configPath,
                    line: reference.line,
                  })}
                  {reference.hostPatterns.length > 0 ? ` (${reference.hostPatterns.join(" ")})` : ""}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      {registering !== null && (
        <form
          aria-labelledby="agent-register-heading"
          className="flex flex-col gap-3 rounded-xl border border-zinc-800 p-4"
          onSubmit={(event) => {
            event.preventDefault();
            void submitRegistration(registering);
          }}
        >
          <h3 id="agent-register-heading" className="font-medium">
            {t("keys.registerHeading", { path: registering.relativePath })}
          </h3>
          <p className="text-sm text-zinc-400">
            {t("keys.registerNote")}
          </p>
          {registering.encrypted && (
            // "Key passphrase", not "Passphrase": the generation form below has
            // a field of its own, and two controls with one name are two
            // controls a user cannot tell apart.
            <label className="block">
              {t("keys.keyPassphrase")}
              <input
                type="password"
                value={agentPassphrase}
                onChange={(event) => setAgentPassphrase(event.target.value)}
              />
            </label>
          )}
          <label className="block">
            {t("keys.lifetime")}
            <select value={String(agentLifetime)} onChange={(event) => setAgentLifetime(Number(event.target.value))}>
              <option value="0">{t("keys.lifetimeForever")}</option>
              <option value="3600">{t("keys.lifetimeHour")}</option>
              <option value="14400">{t("keys.lifetimeFourHours")}</option>
              <option value="43200">{t("keys.lifetimeTwelveHours")}</option>
            </select>
          </label>
          <label className="block">
            <input
              type="checkbox"
              checked={storeInKeychain}
              onChange={(event) => setStoreInKeychain(event.target.checked)}
            />
            {t("keys.storeInKeychain")}
          </label>
          <div className="flex gap-2">
            <button type="submit">{t("keys.registerSubmit")}</button>
            <button type="button" onClick={closeAgentForm}>
              {t("keys.cancel")}
            </button>
          </div>
        </form>
      )}

      {revealing !== null && (
        <RevealDialog
          keyId={revealing.id}
          relativePath={revealing.relativePath}
          api={api}
          onClose={() => setRevealing(null)}
        />
      )}

      {changingPassphrase !== null && (
        <form
          aria-labelledby="passphrase-heading"
          className="flex flex-col gap-3 rounded-xl border border-zinc-800 p-4"
          onSubmit={(event) => {
            event.preventDefault();
            void submitPassphrase(changingPassphrase);
          }}
        >
          <h3 id="passphrase-heading" className="font-medium">
            {t("keys.passphraseHeading", { path: changingPassphrase.relativePath })}
          </h3>
          <p className="text-sm text-zinc-400">
            {t("keys.passphraseNote")}
          </p>
          <label className="block">
            {t("keys.currentPassphrase")}
            <input
              type="password"
              value={currentPassphrase}
              onChange={(event) => setCurrentPassphrase(event.target.value)}
            />
          </label>
          <label className="block">
            {t("keys.newPassphrase")}
            <input
              type="password"
              value={newPassphrase}
              onChange={(event) => setNewPassphrase(event.target.value)}
              disabled={removePassphrase}
            />
          </label>
          <label className="block">
            <input
              type="checkbox"
              checked={removePassphrase}
              onChange={(event) => {
                setRemovePassphrase(event.target.checked);
                setNewPassphrase("");
              }}
            />
            {t("keys.removePassphrase")}
          </label>
          <div className="flex gap-2">
            <button type="submit">{t("keys.savePassphrase")}</button>
            <button type="button" onClick={closePassphraseForm}>
              {t("keys.cancel")}
            </button>
          </div>
        </form>
      )}

      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          void submitGeneration();
        }}
      >
        <h3 className="font-medium">{t("keys.createHeading")}</h3>
        <label className="block">
          {t("keys.algorithm")}
          <select value={algorithm} onChange={(event) => setAlgorithm(event.target.value)}>
            {variants.map((variant) => (
              <option key={`${variant.algorithm}-${variant.bits}`} value={variant.algorithm}>
                {variant.label}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          {t("keys.fileName")}
          <input value={fileName} onChange={(event) => setFileName(event.target.value)} />
        </label>
        <label className="block">
          {t("keys.comment")}
          <input value={comment} onChange={(event) => setComment(event.target.value)} />
        </label>
        {inProcess && (
          <>
            <label className="block">
              {t("keys.passphrase")}
              <input
                type="password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                disabled={unencrypted}
              />
            </label>
            <label className="block">
              <input
                type="checkbox"
                checked={unencrypted}
                onChange={(event) => {
                  setUnencrypted(event.target.checked);
                  setPassphrase("");
                }}
              />
              {t("keys.createUnencrypted")}
            </label>
          </>
        )}
        <button type="submit">{inProcess ? t("keys.createSubmit") : t("keys.showTerminalCommand")}</button>
      </form>

      {terminalCommand !== null && (
        <div>
          <p className="text-sm text-zinc-300">
            {t("keys.hardwareNote")}
          </p>
          <pre aria-label={t("copy.terminalCommand")} className="overflow-x-auto rounded-md bg-zinc-950 p-4 text-xs">
            {terminalCommand.join(" ")}
          </pre>
          <div className="mt-2">
            <CopyButton value={terminalCommand.join(" ")} label="copy.terminalCommand" />
          </div>
        </div>
      )}

      <div>
        <h3 className="font-medium">{t("keys.trashHeading")}</h3>
        <p className="text-sm text-zinc-400">
          {t("keys.trashNote")}
        </p>
        <table className="w-full text-left text-sm">
          <caption className="sr-only">{t("keys.trashCaption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("keys.colFiles")}</th>
              <th scope="col">{t("keys.colAge")}</th>
              <th scope="col">{t("keys.colStatus")}</th>
              <th scope="col">{t("keys.colActions")}</th>
            </tr>
          </thead>
          <tbody>
            {trash.entries.map((entry) => (
              <tr key={entry.id}>
                <td>{entry.files.map((file) => file.originalRelativePath).join(", ")}</td>
                <td>
                  {entry.stale
                    ? t("keys.ageStale", { days: entry.ageDays, retention: trash.retentionDays })
                    : t("keys.age", { days: entry.ageDays })}
                </td>
                <td>{entry.restorable ? t("keys.restorable") : entry.blockers.join(", ")}</td>
                <td>
                  <button type="button" onClick={() => void restore(entry.id)}>
                    {t("keys.restore")}
                  </button>
                  {pendingPurge === entry.id ? (
                    <>
                      <span>{t("keys.purgeWarning")}</span>
                      <button type="button" onClick={() => void purge(entry.id)}>
                        {t("keys.confirmPurge")}
                      </button>
                      <button type="button" onClick={() => setPendingPurge("")}>
                        {t("keys.cancel")}
                      </button>
                    </>
                  ) : (
                    <button type="button" onClick={() => setPendingPurge(entry.id)}>
                      {t("keys.purge")}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

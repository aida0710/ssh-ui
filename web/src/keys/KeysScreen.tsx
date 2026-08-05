import { useCallback, useEffect, useState } from "react";
import { RevealDialog } from "./RevealDialog";
import { CopyButton } from "../ui/CopyButton";
import { useTranslate, type Translate } from "../i18n/context";
import {
  CheckboxField,
  Field,
  control,
  primaryAction,
  secondaryAction,
  sectionCard,
  sectionHeading,
  tableHeadCell,
  tableHeadRow,
} from "../ui/form";
import type { MessageKey } from "../i18n/messages";
import {
  keysApi,
  type KeyCertificate,
  type KeyInventoryResponse,
  type KeyItem,
  type KeysApi,
  type KeyVariant,
  type RelocateKeyResponse,
  type TrashListResponse,
} from "./api";

// groups are the declared group names, supplied by the shell from the overview.
// The Keys screen never infers them: a directory is a group because a line in
// ~/.ssh/config says so, and only the configuration engine reads that line.
type KeysScreenProps = { api?: KeysApi; groups?: string[] };

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

// A row's actions were bare buttons in a table with no rules, so they ran
// together as text and read as prose rather than as controls. The border and
// these classes are what separate one key from the next.
const rowAction = "rounded border border-zinc-700 px-2 py-1 text-xs hover:bg-zinc-800 disabled:text-zinc-600";
const rowDanger = "rounded border border-rose-700 px-2 py-1 text-xs text-rose-300 hover:bg-rose-950";

const noteLabels: Record<string, MessageKey> = {
  fingerprint_unavailable: "keys.noteFingerprintUnavailable",
  symbolic_link: "keys.noteSymbolicLink",
  empty_file: "keys.noteEmptyFile",
  not_regular_file: "keys.noteNotRegularFile",
  comment_not_preserved: "keys.noteCommentNotPreserved",
  keychain_entry_stale: "keys.noteKeychainEntryStale",
};

// A blocker is a stable code, ':' and the detail it is about. The code decides
// the sentence and the detail fills it in, so a reason the server adds later
// still shows the path it names instead of being dropped.
const blockerLabels: Record<string, MessageKey> = {
  key_destination_occupied: "keys.blockerTargetOccupied",
  key_reference_unresolved: "keys.blockerUnresolved",
  key_reference_outside_workspace: "keys.blockerReferenceExternal",
  key_group_not_declared: "keys.blockerGroupNotDeclared",
  key_destination_is_config: "keys.blockerDestinationIsConfig",
  key_in_state_directory: "keys.blockerStateDirectory",
};

function describeBlocker(blocker: string, t: Translate): string {
  const separator = blocker.indexOf(":");
  const code = separator < 0 ? blocker : blocker.slice(0, separator);
  const detail = separator < 0 ? blocker : blocker.slice(separator + 1);
  return t(blockerLabels[code] ?? "keys.blockerOther", { detail });
}

// renameable reports whether this application can rename a file without having
// to decide something the user has not told it.
//
// A private key takes its own public key and certificate with it, so it is
// always renameable. A public key or certificate is renameable only when no
// private key in the inventory belongs to it: renaming half of a pair would
// leave two files that OpenSSH still pairs by name and a reader no longer can,
// so the server refuses it and the button is not offered either.
function renameable(item: KeyItem, items: KeyItem[]): boolean {
  if (item.kind === "private_key") return true;
  if (item.kind !== "public_key" && item.kind !== "certificate") return false;
  const fingerprint =
    item.kind === "certificate" && item.certificate !== undefined
      ? item.certificate.signedKeyFingerprint
      : item.fingerprint;
  if (fingerprint === "") return true;
  return !items.some((candidate) => candidate.kind === "private_key" && candidate.fingerprint === fingerprint);
}

// groupOfKeyPath reads a key's group out of where it sits, mirroring the
// server's rule: keys/<group>/<file>, and nothing else is in a group.
export function groupOfKeyPath(relativePath: string): string {
  const segments = relativePath.split("/");
  if (segments.length < 3 || segments[0] !== "keys") return "";
  return segments.slice(1, -1).join("/");
}

// relocateStem is the part of the name the user is being asked to replace. It
// mirrors the server's rule, so the field starts at the name the relocation
// would actually change rather than at one the server would refuse.
function relocateStem(item: KeyItem): string {
  const base = item.relativePath.split("/").pop() ?? item.relativePath;
  if (item.kind === "private_key") return base;
  for (const suffix of ["-cert.pub", ".pub"]) {
    if (base.endsWith(suffix) && base.length > suffix.length) return base.slice(0, -suffix.length);
  }
  return base;
}

// agentHolds reports whether the agent is currently holding this key, matched
// by fingerprint because that is the only thing an agent identity and an
// inventory item have in common: the agent knows nothing about file paths.
function agentHolds(inventory: KeyInventoryResponse, item: KeyItem): boolean {
  if (!inventory.agentAvailable || item.fingerprint === "") return false;
  return inventory.agentIdentities.some((identity) => identity.fingerprint === item.fingerprint);
}

export function KeysScreen({ api = keysApi, groups = [] }: KeysScreenProps) {
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
  const [relocating, setRelocating] = useState<KeyItem | null>(null);
  const [newName, setNewName] = useState("");
  const [newGroup, setNewGroup] = useState("");
  const [relocated, setRelocated] = useState<RelocateKeyResponse | null>(null);
  const [createGroup, setCreateGroup] = useState("");
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
        const response = await api.hardwareCommand({ algorithm, fileName, group: createGroup, comment });
        setTerminalCommand(response.command);
        return;
      }
      await api.generate({
        algorithm,
        bits: selected?.bits ?? 0,
        fileName,
        group: createGroup,
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

  // The agent is asked to give a key back. Nothing is destroyed, so there is no
  // confirmation: the worst outcome is one more passphrase prompt. The answer
  // carries what the agent holds afterwards, which is what the screen reloads.
  async function removeFromAgent(keyId: string) {
    try {
      await api.deregisterFromAgent(keyId);
      await refresh();
    } catch {
      setFailure(t("keys.agentRemoveFailed"));
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

  function closeRelocateForm() {
    setNewName("");
    setNewGroup("");
    setRelocating(null);
  }

  // A blocked relocation is not a failure to report and forget: the server
  // wrote nothing and said why, so the reasons stay on screen and the form
  // stays open with what the user typed still in it.
  async function submitRelocation(item: KeyItem) {
    setFailure("");
    setRelocated(null);
    try {
      const currentGroup = groupOfKeyPath(item.relativePath);
      const response = await api.relocate(item.id, {
        ...(newName === relocateStem(item) ? {} : { newName }),
        ...(newGroup === currentGroup ? {} : { group: newGroup }),
      });
      setRelocated(response);
      if (response.blockers.length > 0) return;
      closeRelocateForm();
      await refresh();
    } catch {
      setFailure(t("keys.relocateFailed"));
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

      <div className="overflow-x-auto">
      <table className="w-full min-w-[56rem] text-left text-sm">
        <caption className="sr-only">{t("keys.tableCaption")}</caption>
        <thead>
          <tr className={tableHeadRow}>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colFile")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colKind")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colAlgorithm")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colFingerprint")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colPermissions")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colUsedBy")}</th>
            <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colActions")}</th>
          </tr>
        </thead>
        <tbody>
          {inventory.items.map((item) => (
            <tr key={item.id} className="border-b border-zinc-800 align-top">
              <td className="py-2 pr-3 font-mono text-xs">{item.relativePath}</td>
              <td className="py-2 pr-3">
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
              <td className="py-2 pr-3">{item.bits > 0 ? `${item.algorithm} · ${item.bits}` : item.algorithm}</td>
              <td className="py-2 pr-3 font-mono text-xs break-all">
                {item.fingerprint !== "" ? item.fingerprint : null}
                {item.notes.map((note) => (
                  <span key={note} className="ml-2 text-amber-300">
                    {note in noteLabels ? t(noteLabels[note]!) : note}
                  </span>
                ))}
              </td>
              <td className="py-2 pr-3">
                {item.permission}
                {item.permissionRisk && <span className="ml-2 text-red-300">{t("keys.permissionRisk")}</span>}
              </td>
              <td className="py-2 pr-3">
                {item.references.map((reference) => reference.hostPatterns.join(" ")).join(", ")}
              </td>
              <td className="py-2">
                <div className="flex flex-wrap gap-1">
                {(item.kind === "public_key" || item.kind === "certificate") && (
                  <button type="button" className={rowAction} onClick={() => void showPublicKey(item)}>
                    {t("keys.showPublicKey")}
                  </button>
                )}
                {item.kind === "private_key" && (
                  <>
                    <button type="button" className={rowAction} onClick={() => setRevealing(item)}>
                      {t("keys.showPrivateKey")}
                    </button>
                    <button
                      type="button"
                      className={rowAction}
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
                      className={rowAction}
                      disabled={!inventory.agentAvailable}
                      onClick={() => {
                        closePassphraseForm();
                        closeAgentForm();
                        setRegistering(item);
                      }}
                    >
                      {t("keys.addToAgent")}
                    </button>
                    {agentHolds(inventory, item) && (
                      <button
                        type="button"
                        className={rowAction}
                        onClick={() => void removeFromAgent(item.id)}
                      >
                        {t("keys.removeFromAgent")}
                      </button>
                    )}
                    <button type="button" className={rowAction} onClick={() => void moveToTrash(item.id)}>
                      {t("keys.moveToTrash")}
                    </button>
                  </>
                )}
                {renameable(item, inventory.items) && (
                  <button
                    type="button"
                    className={rowAction}
                    onClick={() => {
                      closePassphraseForm();
                      closeAgentForm();
                      setRelocated(null);
                      setNewName(relocateStem(item));
                      setNewGroup(groupOfKeyPath(item.relativePath));
                      setRelocating(item);
                    }}
                  >
                    {t("keys.relocate")}
                  </button>
                )}
                </div>
              </td>
            </tr>
          ))}
          {inventory.items.length === 0 && (
            <tr>
              <td colSpan={7} className="py-3 text-sm text-zinc-400">
                {t("keys.inventoryEmpty")}
              </td>
            </tr>
          )}
        </tbody>
      </table>
      </div>

      {publicKeyView !== null && (
        <section aria-labelledby="public-key-heading" className={sectionCard}>
          <h3 id="public-key-heading" className={sectionHeading}>
            {t("keys.publicKeyHeading", { path: publicKeyView.relativePath })}
          </h3>
          <pre aria-label={t("keys.publicKeyLabel")} className="overflow-x-auto rounded-md bg-zinc-950 p-4 text-xs">
            {publicKeyView.text}
          </pre>
          <div className="flex gap-2">
            <CopyButton value={publicKeyView.text} label="copy.publicKey" />
            <button type="button" className={secondaryAction} onClick={() => setPublicKeyView(null)}>
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
          <h3 id="unreadable-heading" className="text-sm font-medium text-amber-300">
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
          <h3 id="unresolved-heading" className="text-sm font-medium text-amber-300">
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
        <h3 id="agent-heading" className={sectionHeading}>
          {t("keys.agentHeading")}
        </h3>
        {inventory.agentAvailable ? (
          inventory.agentIdentities.length === 0 ? (
            <p className="text-sm text-zinc-400">{t("keys.agentEmpty")}</p>
          ) : (
            <table className="w-full min-w-[32rem] text-left text-sm">
              <caption className="sr-only">{t("keys.agentIdentitiesCaption")}</caption>
              <thead>
                <tr className={tableHeadRow}>
                  <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colAlgorithm")}</th>
                  <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colFingerprint")}</th>
                  <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colComment")}</th>
                </tr>
              </thead>
              <tbody>
                {inventory.agentIdentities.map((identity) => (
                  <tr key={identity.fingerprint} className="border-b border-zinc-800">
                    <td className="py-2 pr-3">
                      {identity.bits > 0 ? `${identity.algorithm} · ${identity.bits}` : identity.algorithm}
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs break-all">{identity.fingerprint}</td>
                    <td className="py-2">{identity.comment}</td>
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
          className={sectionCard}
          onSubmit={(event) => {
            event.preventDefault();
            void submitRegistration(registering);
          }}
        >
          <h3 id="agent-register-heading" className={sectionHeading}>
            {t("keys.registerHeading", { path: registering.relativePath })}
          </h3>
          <p className="text-sm text-zinc-400">{t("keys.registerNote")}</p>
          <div className="grid gap-4 sm:grid-cols-2">
            {registering.encrypted && (
              // "Key passphrase", not "Passphrase": the generation form below
              // has a field of its own, and two controls with one name are two
              // controls a user cannot tell apart.
              <Field label={t("keys.keyPassphrase")}>
                <input
                  className={control}
                  type="password"
                  value={agentPassphrase}
                  onChange={(event) => setAgentPassphrase(event.target.value)}
                />
              </Field>
            )}
            <Field label={t("keys.lifetime")}>
              <select
                className={control}
                value={String(agentLifetime)}
                onChange={(event) => setAgentLifetime(Number(event.target.value))}
              >
                <option value="0">{t("keys.lifetimeForever")}</option>
                <option value="3600">{t("keys.lifetimeHour")}</option>
                <option value="14400">{t("keys.lifetimeFourHours")}</option>
                <option value="43200">{t("keys.lifetimeTwelveHours")}</option>
              </select>
            </Field>
          </div>
          <CheckboxField
            label={t("keys.storeInKeychain")}
            checked={storeInKeychain}
            onChange={setStoreInKeychain}
          />
          <div className="flex gap-2">
            <button type="submit" className={primaryAction}>
              {t("keys.registerSubmit")}
            </button>
            <button type="button" className={secondaryAction} onClick={closeAgentForm}>
              {t("keys.cancel")}
            </button>
          </div>
        </form>
      )}

      {relocating !== null && (
        <form
          aria-labelledby="relocate-heading"
          className={sectionCard}
          onSubmit={(event) => {
            event.preventDefault();
            void submitRelocation(relocating);
          }}
        >
          <h3 id="relocate-heading" className={sectionHeading}>
            {t("keys.relocateHeading", { path: relocating.relativePath })}
          </h3>
          <p className="text-sm text-zinc-400">{t("keys.relocateNote")}</p>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("keys.relocateNewName")}>
              <input className={control} value={newName} onChange={(event) => setNewName(event.target.value)} />
            </Field>
            <Field label={t("keys.relocateGroup")}>
              <select className={control} value={newGroup} onChange={(event) => setNewGroup(event.target.value)}>
                <option value="">{t("keys.groupNone")}</option>
                {groups.map((group) => (
                  <option key={group} value={group}>
                    {group}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <div className="flex gap-2">
            <button type="submit" className={primaryAction}>
              {t("keys.relocateSubmit")}
            </button>
            <button type="button" className={secondaryAction} onClick={closeRelocateForm}>
              {t("keys.cancel")}
            </button>
          </div>
        </form>
      )}

      {/*
        What a rename did, or what stopped it. Both are the same list of facts:
        which files moved, which configuration lines were rewritten, and what
        this application decided not to touch. A rename that only said "done"
        would hide the part the user cannot check for themselves.
      */}
      {relocated !== null && (
        <section
          aria-labelledby="relocate-result-heading"
          className={`${sectionCard} gap-2 text-sm`}
        >
          <h3 id="relocate-result-heading" className={sectionHeading}>
            {relocated.blockers.length > 0
              ? t("keys.relocateRefused")
              : t("keys.relocateDone", { path: relocated.relativePath })}
          </h3>
          {relocated.blockers.length > 0 && (
            <ul role="alert" className="text-amber-300">
              {relocated.blockers.map((blocker) => (
                <li key={blocker}>{describeBlocker(blocker, t)}</li>
              ))}
            </ul>
          )}
          {relocated.files.length > 0 && (
            <>
              <h4 className="text-xs uppercase tracking-wide text-zinc-400">{t("keys.relocateMoved")}</h4>
              <ul className="font-mono text-xs text-zinc-300">
                {relocated.files.map((file) => (
                  <li key={file.from}>{t("keys.relocateFilePair", { from: file.from, to: file.to })}</li>
                ))}
              </ul>
            </>
          )}
          {relocated.references.length > 0 && (
            <>
              <h4 className="text-xs uppercase tracking-wide text-zinc-400">{t("keys.relocateRewritten")}</h4>
              <ul className="text-xs text-zinc-300">
                {relocated.references.map((reference) => (
                  <li key={`${reference.configPath}:${reference.line}:${reference.from}`}>
                    {t("keys.relocateReference", {
                      directive: reference.directive,
                      from: reference.from,
                      to: reference.to,
                      path: reference.configPath,
                      line: reference.line,
                    })}
                  </li>
                ))}
              </ul>
            </>
          )}
          {relocated.skipped.length > 0 && (
            <p className="text-zinc-400">{t("keys.relocateSkipped", { paths: relocated.skipped.join(", ") })}</p>
          )}
          {relocated.notes.map((note) => (
            <p key={note} className="text-amber-300">
              {note in noteLabels ? t(noteLabels[note]!) : note}
            </p>
          ))}
          <div>
            <button type="button" className={secondaryAction} onClick={() => setRelocated(null)}>
              {t("keys.close")}
            </button>
          </div>
        </section>
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
          className={sectionCard}
          onSubmit={(event) => {
            event.preventDefault();
            void submitPassphrase(changingPassphrase);
          }}
        >
          <h3 id="passphrase-heading" className={sectionHeading}>
            {t("keys.passphraseHeading", { path: changingPassphrase.relativePath })}
          </h3>
          <p className="text-sm text-zinc-400">{t("keys.passphraseNote")}</p>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("keys.currentPassphrase")}>
              <input
                className={control}
                type="password"
                value={currentPassphrase}
                onChange={(event) => setCurrentPassphrase(event.target.value)}
              />
            </Field>
            <Field label={t("keys.newPassphrase")}>
              <input
                className={control}
                type="password"
                value={newPassphrase}
                onChange={(event) => setNewPassphrase(event.target.value)}
                disabled={removePassphrase}
              />
            </Field>
          </div>
          <CheckboxField
            label={t("keys.removePassphrase")}
            checked={removePassphrase}
            onChange={(checked) => {
              setRemovePassphrase(checked);
              setNewPassphrase("");
            }}
          />
          <div className="flex gap-2">
            <button type="submit" className={primaryAction}>
              {t("keys.savePassphrase")}
            </button>
            <button type="button" className={secondaryAction} onClick={closePassphraseForm}>
              {t("keys.cancel")}
            </button>
          </div>
        </form>
      )}

      <form
        aria-labelledby="create-key-heading"
        className={sectionCard}
        onSubmit={(event) => {
          event.preventDefault();
          void submitGeneration();
        }}
      >
        <h3 id="create-key-heading" className={sectionHeading}>
          {t("keys.createHeading")}
        </h3>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("keys.algorithm")}>
            <select className={control} value={algorithm} onChange={(event) => setAlgorithm(event.target.value)}>
              {variants.map((variant) => (
                <option key={`${variant.algorithm}-${variant.bits}`} value={variant.algorithm}>
                  {variant.label}
                </option>
              ))}
            </select>
          </Field>
          <Field label={t("keys.createGroup")}>
            <select className={control} value={createGroup} onChange={(event) => setCreateGroup(event.target.value)}>
              <option value="">{t("keys.groupNone")}</option>
              {groups.map((group) => (
                <option key={group} value={group}>
                  {group}
                </option>
              ))}
            </select>
          </Field>
          <Field label={t("keys.fileName")}>
            <input className={control} value={fileName} onChange={(event) => setFileName(event.target.value)} />
          </Field>
          <Field label={t("keys.comment")}>
            <input className={control} value={comment} onChange={(event) => setComment(event.target.value)} />
          </Field>
          {inProcess && (
            <Field label={t("keys.passphrase")}>
              <input
                className={control}
                type="password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                disabled={unencrypted}
              />
            </Field>
          )}
        </div>
        {inProcess && (
          <CheckboxField
            label={t("keys.createUnencrypted")}
            checked={unencrypted}
            onChange={(checked) => {
              setUnencrypted(checked);
              setPassphrase("");
            }}
          />
        )}
        <button type="submit" className={`self-start ${primaryAction}`}>
          {inProcess ? t("keys.createSubmit") : t("keys.showTerminalCommand")}
        </button>
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

      <div className="flex flex-col gap-2">
        <h3 className={sectionHeading}>{t("keys.trashHeading")}</h3>
        <p className="text-sm text-zinc-400">{t("keys.trashNote")}</p>
        <div className="overflow-x-auto">
        <table className="w-full min-w-[40rem] text-left text-sm">
          <caption className="sr-only">{t("keys.trashCaption")}</caption>
          <thead>
            <tr className={tableHeadRow}>
              <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colFiles")}</th>
              <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colAge")}</th>
              <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colStatus")}</th>
              <th scope="col" className={`${tableHeadCell} whitespace-nowrap`}>{t("keys.colActions")}</th>
            </tr>
          </thead>
          <tbody>
            {trash.entries.map((entry) => (
              <tr key={entry.id} className="border-b border-zinc-800 align-top">
                <td className="py-2 pr-3 font-mono text-xs">
                  {entry.files.map((file) => file.originalRelativePath).join(", ")}
                </td>
                <td className="py-2 pr-3">
                  {entry.stale
                    ? t("keys.ageStale", { days: entry.ageDays, retention: trash.retentionDays })
                    : t("keys.age", { days: entry.ageDays })}
                </td>
                <td className="py-2 pr-3">{entry.restorable ? t("keys.restorable") : entry.blockers.join(", ")}</td>
                <td className="py-2">
                  <div className="flex flex-wrap items-center gap-1">
                  <button type="button" className={rowAction} onClick={() => void restore(entry.id)}>
                    {t("keys.restore")}
                  </button>
                  {pendingPurge === entry.id ? (
                    <>
                      <span>{t("keys.purgeWarning")}</span>
                      <button type="button" className={rowDanger} onClick={() => void purge(entry.id)}>
                        {t("keys.confirmPurge")}
                      </button>
                      <button type="button" className={rowAction} onClick={() => setPendingPurge("")}>
                        {t("keys.cancel")}
                      </button>
                    </>
                  ) : (
                    <button type="button" className={rowDanger} onClick={() => setPendingPurge(entry.id)}>
                      {t("keys.purge")}
                    </button>
                  )}
                  </div>
                </td>
              </tr>
            ))}
            {trash.entries.length === 0 && (
              <tr>
                <td colSpan={4} className="py-3 text-sm text-zinc-400">
                  {t("keys.trashEmpty")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        </div>
      </div>
    </section>
  );
}

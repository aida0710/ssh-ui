import { useCallback, useEffect, useState } from "react";
import { RevealDialog } from "./RevealDialog";
import { CopyButton } from "../ui/CopyButton";
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
function certificateLines(certificate: KeyCertificate, now: number): { text: string; expired: boolean }[] {
  const lines: { text: string; expired: boolean }[] = [];
  if (certificate.keyId !== "") lines.push({ text: `key id ${certificate.keyId}`, expired: false });
  if (certificate.principals.length > 0) {
    lines.push({ text: `for ${certificate.principals.join(", ")}`, expired: false });
  } else {
    // A certificate with no principal is valid for every user on the host that
    // trusts its CA. That is a fact about its reach, not a missing field.
    lines.push({ text: "for any principal", expired: false });
  }
  if (certificate.neverExpires) {
    lines.push({ text: "never expires", expired: false });
  } else {
    const expiry = new Date(certificate.validBefore * 1000);
    const expired = certificate.validBefore * 1000 <= now;
    lines.push({
      text: `${expired ? "expired" : "valid until"} ${expiry.toISOString().slice(0, 16).replace("T", " ")}Z`,
      expired,
    });
  }
  if (certificate.signedKeyType !== "") {
    lines.push({
      text: `signs ${certificate.signedKeyType} ${certificate.signedKeyFingerprint}`.trim(),
      expired: false,
    });
  }
  return lines;
}

const noteLabels: Record<string, string> = {
  fingerprint_unavailable: "Fingerprint unavailable",
  symbolic_link: "Symbolic link, not followed",
  empty_file: "Empty file",
  not_regular_file: "Not a regular file",
  comment_not_preserved: "Comment not preserved",
};

export function KeysScreen({ api = keysApi }: KeysScreenProps) {
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
      setFailure("The key could not be created. Check the name, the algorithm and the passphrase.");
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
      setFailure("The passphrase could not be changed. Check the current passphrase and try again.");
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
      setFailure(
        "The key could not be added to the agent. Check the passphrase, and that an agent this process can reach is running.",
      );
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
      setFailure("The public key could not be read.");
    }
  }

  async function moveToTrash(keyId: string) {
    setFailure("");
    try {
      await api.trash(keyId);
      await refresh();
    } catch {
      setFailure("The key could not be moved to the trash.");
    }
  }

  async function restore(entryId: string) {
    setFailure("");
    try {
      const response = await api.restore(entryId);
      if (response.blockers.length > 0) {
        setFailure(`Restore refused: ${response.blockers.join(", ")}`);
        return;
      }
      await refresh();
    } catch {
      setFailure("The entry could not be restored.");
    }
  }

  async function purge(entryId: string) {
    setFailure("");
    try {
      await api.purge(entryId);
      setPendingPurge("");
      await refresh();
    } catch {
      setFailure("The entry could not be deleted permanently.");
    }
  }

  if (state === "loading") {
    return <p aria-live="polite">Reading the ssh directory…</p>;
  }
  if (state === "error" || inventory === null || trash === null) {
    return <p role="alert">The ssh directory could not be read. Restart ssh-ui and try again.</p>;
  }

  return (
    <section aria-labelledby="keys-heading" className="flex flex-col gap-8">
      <h2 id="keys-heading" className="text-lg font-medium">
        Keys
      </h2>
      {failure !== "" && (
        <p role="alert" className="rounded-md border border-red-800 p-3 text-sm text-red-300">
          {failure}
        </p>
      )}

      <table className="w-full text-left text-sm">
        <caption className="sr-only">Files classified by content and permissions</caption>
        <thead>
          <tr>
            <th scope="col">File</th>
            <th scope="col">Kind</th>
            <th scope="col">Algorithm</th>
            <th scope="col">Fingerprint</th>
            <th scope="col">Permissions</th>
            <th scope="col">Used by</th>
            <th scope="col">Actions</th>
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
                    {certificateLines(item.certificate, now).map((line) => (
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
                    {noteLabels[note] ?? note}
                  </span>
                ))}
              </td>
              <td>
                {item.permission}
                {item.permissionRisk && <span className="ml-2 text-red-300">Permissions too open</span>}
              </td>
              <td>{item.references.map((reference) => reference.hostPatterns.join(" ")).join(", ")}</td>
              <td>
                {(item.kind === "public_key" || item.kind === "certificate") && (
                  <button type="button" onClick={() => void showPublicKey(item)}>
                    Show public key
                  </button>
                )}
                {item.kind === "private_key" && (
                  <>
                    <button type="button" onClick={() => setRevealing(item)}>
                      Show private key
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        closePassphraseForm();
                        closeAgentForm();
                        setChangingPassphrase(item);
                      }}
                    >
                      Change passphrase
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
                      Add to agent
                    </button>
                    <button type="button" onClick={() => void moveToTrash(item.id)}>
                      Move to trash
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
            {`Public key: ${publicKeyView.relativePath}`}
          </h3>
          <pre aria-label="Public key" className="overflow-x-auto rounded-md bg-zinc-950 p-4 text-xs">
            {publicKeyView.text}
          </pre>
          <div className="flex gap-2">
            <CopyButton value={publicKeyView.text} label="copy.publicKey" />
            <button type="button" onClick={() => setPublicKeyView(null)}>
              Close
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
            Files this scan could not classify
          </h3>
          <p className="text-sm text-zinc-400">
            These are inside ~/.ssh and are missing from the table above. Nothing was changed about them.
          </p>
          <ul className="text-sm text-zinc-300">
            {inventory.unreadable.map((file) => (
              <li key={file.relativePath}>{`${file.relativePath} — ${file.reason}`}</li>
            ))}
          </ul>
        </section>
      )}

      {inventory.unresolvedReferences.length > 0 && (
        <section aria-labelledby="unresolved-heading" className="flex flex-col gap-2">
          <h3 id="unresolved-heading" className="font-medium text-amber-300">
            Configuration entries pointing at a key that is not there
          </h3>
          <ul className="text-sm text-zinc-300">
            {inventory.unresolvedReferences.map((reference) => (
              <li key={`${reference.configPath}:${reference.line}:${reference.value}`}>
                {`${reference.directive} ${reference.value} — ${reference.configPath}:${reference.line} (${reference.reason})`}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby="agent-heading" className="flex flex-col gap-2">
        <h3 id="agent-heading" className="font-medium">
          ssh-agent
        </h3>
        {inventory.agentAvailable ? (
          inventory.agentIdentities.length === 0 ? (
            <p className="text-sm text-zinc-400">An agent is reachable and holds no identity yet.</p>
          ) : (
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Identities the agent currently holds</caption>
              <thead>
                <tr>
                  <th scope="col">Algorithm</th>
                  <th scope="col">Fingerprint</th>
                  <th scope="col">Comment</th>
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
            No agent is reachable from this process, so registration is unavailable. ssh-add needs both an ssh-add
            program and an SSH_AUTH_SOCK to talk to.
          </p>
        )}
        {inventory.agentDelegations.length > 0 && (
          <>
            <p className="text-sm text-zinc-400">
              These configuration entries expect the agent to supply a key rather than naming a file:
            </p>
            <ul className="text-sm text-zinc-300">
              {inventory.agentDelegations.map((reference) => (
                <li key={`${reference.configPath}:${reference.line}`}>
                  {`${reference.directive} ${reference.value} — ${reference.configPath}:${reference.line}`}
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
            {`Add to agent: ${registering.relativePath}`}
          </h3>
          <p className="text-sm text-zinc-400">
            The passphrase is handed to ssh-add on standard input, so it reaches neither the command line nor the
            child environment. ssh-ui does not store it. The login Keychain is the only place it can outlive this
            request, and only if you ask for that below.
          </p>
          {registering.encrypted && (
            // "Key passphrase", not "Passphrase": the generation form below has
            // a field of its own, and two controls with one name are two
            // controls a user cannot tell apart.
            <label className="block">
              Key passphrase
              <input
                type="password"
                value={agentPassphrase}
                onChange={(event) => setAgentPassphrase(event.target.value)}
              />
            </label>
          )}
          <label className="block">
            Lifetime
            <select value={String(agentLifetime)} onChange={(event) => setAgentLifetime(Number(event.target.value))}>
              <option value="0">Until the agent exits</option>
              <option value="3600">1 hour</option>
              <option value="14400">4 hours</option>
              <option value="43200">12 hours</option>
            </select>
          </label>
          <label className="block">
            <input
              type="checkbox"
              checked={storeInKeychain}
              onChange={(event) => setStoreInKeychain(event.target.checked)}
            />
            Also store the passphrase in the login Keychain, so macOS unlocks this key without asking again
          </label>
          <div className="flex gap-2">
            <button type="submit">Register with the agent</button>
            <button type="button" onClick={closeAgentForm}>
              Cancel
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
            {`Change passphrase: ${changingPassphrase.relativePath}`}
          </h3>
          <p className="text-sm text-zinc-400">
            The passphrase is used only for this change. ssh-ui never stores it. Use “Add to agent” with the login
            Keychain option if you want macOS to remember it.
          </p>
          <label className="block">
            Current passphrase
            <input
              type="password"
              value={currentPassphrase}
              onChange={(event) => setCurrentPassphrase(event.target.value)}
            />
          </label>
          <label className="block">
            New passphrase
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
            Remove the passphrase and leave the key unprotected on disk
          </label>
          <div className="flex gap-2">
            <button type="submit">Save new passphrase</button>
            <button type="button" onClick={closePassphraseForm}>
              Cancel
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
        <h3 className="font-medium">Create a key</h3>
        <label className="block">
          Algorithm
          <select value={algorithm} onChange={(event) => setAlgorithm(event.target.value)}>
            {variants.map((variant) => (
              <option key={`${variant.algorithm}-${variant.bits}`} value={variant.algorithm}>
                {variant.label}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          File name
          <input value={fileName} onChange={(event) => setFileName(event.target.value)} />
        </label>
        <label className="block">
          Comment
          <input value={comment} onChange={(event) => setComment(event.target.value)} />
        </label>
        {inProcess && (
          <>
            <label className="block">
              Passphrase
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
              Create without a passphrase, and accept that anyone who reads the file can use the key
            </label>
          </>
        )}
        <button type="submit">{inProcess ? "Create key" : "Show Terminal command"}</button>
      </form>

      {terminalCommand !== null && (
        <div>
          <p className="text-sm text-zinc-300">
            Hardware-backed keys need your security key, so ssh-ui does not create them. Run this command in
            Terminal yourself:
          </p>
          <pre aria-label="Terminal command" className="overflow-x-auto rounded-md bg-zinc-950 p-4 text-xs">
            {terminalCommand.join(" ")}
          </pre>
          <div className="mt-2">
            <CopyButton value={terminalCommand.join(" ")} label="copy.terminalCommand" />
          </div>
        </div>
      )}

      <div>
        <h3 className="font-medium">Trash</h3>
        <p className="text-sm text-zinc-400">
          Deleted keys stay here until you remove them. Nothing is ever deleted automatically.
        </p>
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Soft-deleted keys</caption>
          <thead>
            <tr>
              <th scope="col">Files</th>
              <th scope="col">Age</th>
              <th scope="col">Status</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {trash.entries.map((entry) => (
              <tr key={entry.id}>
                <td>{entry.files.map((file) => file.originalRelativePath).join(", ")}</td>
                <td>
                  {entry.stale
                    ? `${entry.ageDays} days · older than ${trash.retentionDays} days`
                    : `${entry.ageDays} days`}
                </td>
                <td>{entry.restorable ? "Restorable" : entry.blockers.join(", ")}</td>
                <td>
                  <button type="button" onClick={() => void restore(entry.id)}>
                    Restore
                  </button>
                  {pendingPurge === entry.id ? (
                    <>
                      <span>This cannot be undone. There is no backup of a permanently deleted key.</span>
                      <button type="button" onClick={() => void purge(entry.id)}>
                        Confirm permanent delete
                      </button>
                      <button type="button" onClick={() => setPendingPurge("")}>
                        Cancel
                      </button>
                    </>
                  ) : (
                    <button type="button" onClick={() => setPendingPurge(entry.id)}>
                      Delete permanently
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

import { useCallback, useEffect, useState } from "react";
import { RevealDialog } from "./RevealDialog";
import {
  keysApi,
  type KeyInventoryResponse,
  type KeyItem,
  type KeysApi,
  type KeyVariant,
  type TrashListResponse,
} from "./api";

type KeysScreenProps = { api?: KeysApi };

type ScreenState = "loading" | "ready" | "error";

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
              <td>{item.kind}</td>
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
                {item.kind === "private_key" && (
                  <>
                    <button type="button" onClick={() => setRevealing(item)}>
                      Show private key
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        closePassphraseForm();
                        setChangingPassphrase(item);
                      }}
                    >
                      Change passphrase
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
            The passphrase is used only for this change. ssh-ui never stores it. Use agent registration if you
            want macOS to remember it.
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

/**
 * `/vaults`: full-pane screen to manage vault declarations, their passwords and keys.
 * Screen-loop: the fullscreen surface returns an Intent, closes, the matching dialog flow runs with the stock
 * ctx.ui dialogs, then the screen reopens. Dialogs are never stacked over a live surface.
 * Values never leave this process: nothing here is returned to the model.
 */
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import type { JSXNode, UiEvent } from "@oh-my-pi/pi-tui";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import {
  CONFIG_REL,
  VAULT_NAME_RE,
  applyMutation,
  decryptVault,
  encryptVault,
  enroll,
  generateValue,
  loadConfig,
  parseTopLevelKeys,
  passwordCache,
  readIfExists,
  readMasked,
  unlock,
  writeConfig,
  writeVaultFile,
  type KeyBlock,
  type Mutation,
  type VaultConfigEntry,
} from "./ansible-vault.ts";
import { PASSWORD_STORE_LABEL, deleteVaultPassword, isVaultPasswordStored, storeVaultPassword } from "./password-store.ts";
import { bar, button, leafKey, mount, n, prose } from "./tsp-nodes.ts";

type Config = Record<string, VaultConfigEntry>;
type PasswordState = "stored" | "not stored" | "unknown";

interface VaultRow {
  name: string;
  entry: VaultConfigEntry;
  fileExists: boolean;
  password: PasswordState;
}

interface Session {
  selected: string | undefined;
  focus: "vaults" | "keys";
  keySel: string | undefined;
  /** Unlocked vaults: name -> current plaintext. */
  open: Map<string, string>;
  /** `${vault}\0${key}` */
  revealed: Set<string>;
}

type Intent =
  | { k: "close" }
  | { k: "add" }
  | { k: "edit" | "remove" | "password" | "open"; vault: string }
  | { k: "key-add"; vault: string }
  | { k: "key-update" | "key-delete"; vault: string; key: string };

const NEW_ID = "New password id…";
const FORMATS = ["urlsafe", "base64", "hex", "alnum"] as const;
const revealId = (vault: string, key: string) => `${vault}\0${key}`;
const errMsg = (err: unknown) => (err instanceof Error ? err.message : String(err));
const exists = (p: string) => fs.stat(p).then(() => true, () => false);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** A missing config is empty; an invalid one throws (never overwrite it). */
async function readConfig(ctx: ExtensionContext): Promise<Config> {
  return (await exists(path.resolve(ctx.cwd, CONFIG_REL))) ? loadConfig(ctx.cwd) : {};
}

async function loadRows(ctx: ExtensionContext): Promise<VaultRow[] | undefined> {
  let config: Config;
  try {
    config = await readConfig(ctx);
  } catch (err) {
    ctx.ui.notify(errMsg(err), "error");
    return undefined;
  }
  return Promise.all(
    Object.entries(config).map(async ([name, entry]): Promise<VaultRow> => {
      let password: PasswordState;
      try {
        password = (await isVaultPasswordStored(entry.passwordId)) ? "stored" : "not stored";
      } catch {
        password = "unknown";
      }
      return { name, entry, fileExists: await exists(path.resolve(ctx.cwd, entry.file)), password };
    }),
  );
}

/** Raw value text of a key block. Unwraps the `!unsafe "..."` / `"..."` forms this tool writes. */
function rawValue(plaintext: string, b: KeyBlock): string {
  const lines = plaintext.split(/\r?\n/).slice(b.start, b.end);
  lines[0] = lines[0]!.replace(/^[A-Za-z_][A-Za-z0-9_]*\s*:\s?/, "");
  let raw = lines.join("\n").trim().replace(/^!unsafe\s+/, "");
  if (raw.startsWith('"')) {
    try {
      const v: unknown = JSON.parse(raw);
      if (typeof v === "string") raw = v;
    } catch {
      // not a JSON string literal: shown verbatim
    }
  }
  return raw;
}

function keysOf(plaintext: string): { key: string; raw: string }[] | string {
  try {
    return parseTopLevelKeys(plaintext).map(b => ({ key: b.key, raw: rawValue(plaintext, b) }));
  } catch (err) {
    return errMsg(err);
  }
}

// ---------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------

function showScreen(ctx: ExtensionContext, session: Session, rows: VaultRow[]): Promise<Intent> {
  return ctx
    .ui.custom<Intent>(
      (_ui, _theme, _kb, done) =>
        mount(refresh => {
        let closed = false;
        const bump = refresh;
        const finish = (intent: Intent) => {
          if (closed) return;
          closed = true;
          done(intent);
        };

        const row = () => rows.find(r => r.name === session.selected);
        const keys = () => {
          const plaintext = session.selected === undefined ? undefined : session.open.get(session.selected);
          const list = plaintext === undefined ? undefined : keysOf(plaintext);
          if (Array.isArray(list) && !list.some(k => k.key === session.keySel)) session.keySel = list[0]?.key;
          return list;
        };
        const keyDetail = (k: { key: string; raw: string }) =>
          session.revealed.has(revealId(session.selected!, k.key)) ? k.raw.replace(/\s*\n\s*/g, " ") : `${k.raw.length} chars`;

        const move = (d: number) => {
          if (session.focus === "keys") {
            const list = keys();
            if (!Array.isArray(list) || list.length === 0) return;
            const i = list.findIndex(k => k.key === session.keySel);
            session.keySel = list[Math.min(list.length - 1, Math.max(0, i + d))]!.key;
          } else {
            const i = rows.findIndex(r => r.name === session.selected);
            session.selected = rows[Math.min(rows.length - 1, Math.max(0, i + d))]?.name ?? session.selected;
            session.keySel = undefined;
          }
        };

        const act = (a: string) => {
          const vault = session.selected;
          switch (a) {
            case "close":
              return finish({ k: "close" });
            case "add":
              return finish({ k: "add" });
            case "edit":
            case "remove":
            case "password":
            case "open":
              if (vault) finish({ k: a, vault });
              return;
            case "key-add":
              if (vault && session.open.has(vault)) finish({ k: a, vault });
              return;
            case "key-update":
            case "key-delete":
              keys();
              if (vault && session.keySel) finish({ k: a, vault, key: session.keySel });
              return;
            case "reveal": {
              keys();
              if (!vault || !session.keySel) return;
              const id = revealId(vault, session.keySel);
              if (!session.revealed.delete(id)) session.revealed.add(id);
              return bump();
            }
            case "focus":
              if (session.focus === "keys") session.focus = "vaults";
              else if (vault && session.open.has(vault)) session.focus = "keys";
              return bump();
          }
        };

        const onEvent = (e: UiEvent): void => {
          if (e.type === "select" || e.type === "activate") {
            const leaf = leafKey(e.key);
            if (leaf === "vaults") {
              if (session.selected !== e.item) session.keySel = undefined;
              session.selected = e.item;
              session.focus = "vaults";
              if (e.type === "activate") return act("open");
            } else if (leaf === "keys") {
              session.keySel = e.item;
              session.focus = "keys";
            }
          } else if (e.type === "action") {
            return act(e.act);
          }
          bump();
        };

        const body = (): JSXNode => {
          if (rows.length === 0) return prose("No vaults declared. Press a to add one.");
          const sel = row();
          const left = n(
            "list",
            { selected: session.selected },
            rows.map(r => n("item", { label: r.name, detail: r.entry.description ?? r.entry.file }, undefined, r.name)),
            "vaults",
          );
          if (!sel) return left;
          const list = keys();
          const open = session.open.has(sel.name);
          const inner: JSXNode[] = [
            n(
              "kv",
              {
                items: [
                  { k: "file", v: sel.entry.file },
                  { k: "file status", v: sel.fileExists ? "present" : "missing" },
                  { k: "password id", v: sel.entry.passwordId },
                  {
                    k: "password",
                    v: sel.password === "stored" ? `stored in ${PASSWORD_STORE_LABEL}` : sel.password,
                  },
                  { k: "description", v: sel.entry.description ?? "-" },
                ],
              },
              undefined,
              "info",
            ),
          ];
          if (!open) inner.push(prose("Locked. Press Enter to unlock and show keys."));
          else if (typeof list === "string") inner.push(prose(list));
          else if (list && list.length === 0) inner.push(prose("No keys. Press n to add one."));
          else if (list) {
            inner.push(
              n(
                "list",
                { selected: session.keySel },
                list.map(k => n("item", { label: k.key, detail: keyDetail(k) }, undefined, k.key)),
                "keys",
              ),
            );
          }
          return n("row", { gap: "lg", align: "stretch" }, [left, n("card", { head: sel.name, grow: 1 }, inner, "detail")]);
        };

        const dock = (): JSXNode => {
          const keysFocus = session.focus === "keys";
          const hints = keysFocus
            ? "↑↓ select · n new · u set · x delete · r reveal · tab back · esc close"
            : "↑↓ select · a add · e edit · d remove · p password · enter keys · esc close";
          return n("col", { gap: "sm" }, [
            n("status", {}, [
              n("seg", { spans: [{ t: `${rows.length} vaults · ${session.focus}` }], side: "left" }),
              n("seg", { spans: [{ t: hints, s: "muted" }], side: "right" }),
            ]),
            bar(
              keysFocus
                ? [
                    button("New key", "key-add", "n"),
                    button("Set value", "key-update", "u"),
                    button("Delete key", "key-delete", "x"),
                    button("Reveal/Hide", "reveal", "r"),
                    null,
                    button("Back", "focus", "tab"),
                    button("Close", "close", "escape"),
                  ]
                : [
                    button("Add", "add", "a"),
                    button("Edit", "edit", "e"),
                    button("Remove", "remove", "d"),
                    button("Set password", "password", "p"),
                    button("Open keys", "open", "enter"),
                    null,
                    button("Close", "close", "escape"),
                  ],
            ),
          ]);
        };

        return {
          describe: () => n("col", { gap: "sm" }, [body(), dock()]),
          handleEvent: onEvent,
          handleKey(key): void {
            const id = key.id;
            if (id === "escape" || id === "q") return finish({ k: "close" });
            if (id === "up") move(-1);
            else if (id === "down") move(1);
            else if (id === "tab") return act("focus");
            else if (session.focus === "keys") {
              const a = ({ n: "key-add", u: "key-update", x: "key-delete", r: "reveal" } as Record<string, string>)[id];
              if (a) return act(a);
            } else if (id === "enter") return act("open");
            else {
              const a = ({ a: "add", e: "edit", d: "remove", p: "password" } as Record<string, string>)[id];
              if (a) return act(a);
            }
            bump();
          },
        };
        }),
      { overlay: true, fullscreen: true },
    )
    .then(intent => intent ?? { k: "close" });
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

type Ctx = ExtensionContext;

function dropVaultState(session: Session, name: string): void {
  session.open.delete(name);
  for (const id of [...session.revealed]) if (id.startsWith(`${name}\0`)) session.revealed.delete(id);
}

function checkName(name: string, config: Config): void {
  if (!VAULT_NAME_RE.test(name)) throw new Error(`Vault name must match ${VAULT_NAME_RE.source}`);
  if (Object.hasOwn(config, name)) throw new Error(`Vault "${name}" is already declared`);
}

/** Pick an existing id (other than `exclude`) or type a new one. Undefined = cancelled. */
async function pickPasswordId(ctx: Ctx, config: Config, exclude?: string): Promise<string | undefined> {
  const ids = [...new Set(Object.values(config).map(v => v.passwordId))].filter(i => i !== exclude);
  if (ids.length > 0) {
    const choice = await ctx.ui.select("Password id", [...ids, NEW_ID]);
    if (choice === undefined) return undefined;
    if (choice !== NEW_ID) return choice;
  }
  const id = (await ctx.ui.input("New password id"))?.trim();
  if (!id) return undefined;
  if (!VAULT_NAME_RE.test(id)) throw new Error(`Password id must match ${VAULT_NAME_RE.source}`);
  return id;
}

/** Decrypt with a stored password; a failure drops the cache so the next unlock re-prompts. */
async function decryptWithStored(id: string, fileText: string, vault: string, failMsg?: string) {
  const pw = await unlock(id);
  try {
    return { pw, ...decryptVault(fileText, pw, vault) };
  } catch (err) {
    passwordCache.delete(id);
    throw failMsg ? new Error(failMsg) : err;
  }
}

async function typedPassword(ctx: Ctx, id: string, hint: string): Promise<string | undefined> {
  const pw = (await readMasked(ctx, undefined, `Vault password "${id}"`, hint))?.trim();
  return pw || undefined;
}

async function flowOpen(ctx: Ctx, session: Session, row: VaultRow): Promise<void> {
  if (row.password === "not stored") {
    ctx.ui.notify(`Password "${row.entry.passwordId}" is not stored; press p to set it`, "info");
    return;
  }
  const fileText = await readIfExists(path.resolve(ctx.cwd, row.entry.file), "Vault file");
  const { plaintext } = await decryptWithStored(row.entry.passwordId, fileText, row.name);
  session.open.set(row.name, plaintext);
  session.focus = "keys";
  session.keySel = undefined;
}

async function flowAdd(ctx: Ctx, session: Session): Promise<void> {
  const config = await readConfig(ctx);
  const name = (await ctx.ui.input("Vault name"))?.trim();
  if (name === undefined) return;
  checkName(name, config);
  const file = (await ctx.ui.input("Vault file (relative to project)", `ansible/group_vars/${name}/vault.yml`))?.trim();
  if (file === undefined) return;
  if (file === "") throw new Error("Vault file must not be empty");
  const id = await pickPasswordId(ctx, config);
  if (id === undefined) return;
  const description = (await ctx.ui.input("Description (optional)"))?.trim();
  if (description === undefined) return;

  const abs = path.resolve(ctx.cwd, file);
  const stored = await isVaultPasswordStored(id);
  if (await exists(abs)) {
    const fileText = await readIfExists(abs, "Vault file");
    if (stored) await decryptWithStored(id, fileText, name);
    else {
      const pw = await typedPassword(ctx, id, `Must decrypt ${file}`);
      if (pw === undefined) return;
      await enroll(id, pw, name, fileText);
    }
  } else {
    let pw: string;
    if (stored) pw = await unlock(id);
    else {
      const first = await typedPassword(ctx, id, `New vault file ${file}`);
      if (first === undefined) return;
      const again = (await readMasked(ctx, undefined, "Repeat password", undefined))?.trim();
      if (again !== first) throw new Error("Passwords do not match; nothing was written.");
      pw = first;
    }
    await fs.mkdir(path.dirname(abs), { recursive: true });
    // "wx": fail if the file appeared meanwhile.
    await fs.writeFile(abs, encryptVault("---\n", pw, "$ANSIBLE_VAULT;1.1;AES256"), { flag: "wx" });
    if (!stored) {
      await storeVaultPassword(id, pw);
      passwordCache.set(id, pw);
    }
  }
  await writeConfig(ctx.cwd, { ...config, [name]: { file, passwordId: id, ...(description ? { description } : {}) } });
  session.selected = name;
  ctx.ui.notify(`Declared vault "${name}" (${file})`, "info");
}

async function flowEdit(ctx: Ctx, session: Session, vault: string): Promise<void> {
  const config = await readConfig(ctx);
  const entry = config[vault];
  if (!entry) throw new Error(`Unknown vault "${vault}"`);
  const field = await ctx.ui.select(`Edit ${vault}`, ["Name", "File", "Password id", "Description"]);
  if (field === undefined) return;

  if (field === "Name") {
    const next = (await ctx.ui.input("New name", vault))?.trim();
    if (!next || next === vault) return;
    checkName(next, config);
    const renamed = Object.fromEntries(Object.entries(config).map(([k, v]) => [k === vault ? next : k, v]));
    await writeConfig(ctx.cwd, renamed);
    const plaintext = session.open.get(vault);
    const shown = [...session.revealed].filter(id => id.startsWith(`${vault}\0`));
    dropVaultState(session, vault);
    if (plaintext !== undefined) session.open.set(next, plaintext);
    for (const id of shown) session.revealed.add(revealId(next, id.slice(vault.length + 1)));
    session.selected = next;
    ctx.ui.notify(`Renamed vault "${vault}" to "${next}"`, "info");
  } else if (field === "File") {
    const file = (await ctx.ui.input("New file path", entry.file))?.trim();
    if (!file || file === entry.file) return;
    const fileText = await readIfExists(path.resolve(ctx.cwd, file), "Vault file");
    await decryptWithStored(entry.passwordId, fileText, vault);
    await writeConfig(ctx.cwd, { ...config, [vault]: { ...entry, file } });
    dropVaultState(session, vault);
    ctx.ui.notify(`Vault "${vault}" now points to ${file}`, "info");
  } else if (field === "Password id") {
    const id = await pickPasswordId(ctx, config, entry.passwordId);
    if (id === undefined) return;
    const fileText = await readIfExists(path.resolve(ctx.cwd, entry.file), "Vault file");
    if (await isVaultPasswordStored(id)) {
      await decryptWithStored(id, fileText, vault, `Password "${id}" does not decrypt vault "${vault}"; declaration unchanged.`);
    } else {
      const pw = await typedPassword(ctx, id, `Must decrypt ${entry.file}`);
      if (pw === undefined) return;
      await enroll(id, pw, vault, fileText);
    }
    await writeConfig(ctx.cwd, { ...config, [vault]: { ...entry, passwordId: id } });
    dropVaultState(session, vault);
    ctx.ui.notify(`Vault "${vault}" now uses password id "${id}"`, "info");
  } else {
    const input = (await ctx.ui.input("Description (blank keeps, - clears)", entry.description))?.trim();
    if (!input) return;
    const { description: _drop, ...rest } = entry;
    await writeConfig(ctx.cwd, { ...config, [vault]: input === "-" ? rest : { ...rest, description: input } });
    ctx.ui.notify(`Updated description of "${vault}"`, "info");
  }
}

async function flowRemove(ctx: Ctx, session: Session, vault: string): Promise<void> {
  const config = await readConfig(ctx);
  const entry = config[vault];
  if (!entry) throw new Error(`Unknown vault "${vault}"`);
  const ok = await ctx.ui.confirm(
    `Remove vault declaration ${vault}?`,
    `The file ${entry.file} and its stored password stay. Only ${CONFIG_REL} changes.`,
  );
  if (!ok) return;
  const { [vault]: _removed, ...rest } = config;
  await writeConfig(ctx.cwd, rest);
  dropVaultState(session, vault);
  session.selected = undefined;
  session.focus = "vaults";
  ctx.ui.notify(`Removed vault declaration "${vault}"`, "info");

  const id = entry.passwordId;
  if (Object.values(rest).some(v => v.passwordId === id) || !(await isVaultPasswordStored(id))) return;
  const drop = await ctx.ui.confirm(
    `Delete orphaned password ${id}?`,
    `No vault declaration in this project uses it. Other projects on this machine may still use password id ${id}; they would need set_password again.`,
  );
  if (!drop) return;
  await deleteVaultPassword(id);
  passwordCache.delete(id);
  ctx.ui.notify(`Deleted password "${id}" from ${PASSWORD_STORE_LABEL}`, "info");
}

async function flowPassword(ctx: Ctx, vault: string): Promise<void> {
  const config = await readConfig(ctx);
  const entry = config[vault];
  if (!entry) throw new Error(`Unknown vault "${vault}"`);
  const fileText = await readIfExists(path.resolve(ctx.cwd, entry.file), "Vault file");
  const users = Object.entries(config).filter(([, v]) => v.passwordId === entry.passwordId).map(([k]) => k);
  const pw = await typedPassword(ctx, entry.passwordId, `Used by: ${users.join(", ")}`);
  if (pw === undefined) return;
  await enroll(entry.passwordId, pw, vault, fileText);
  ctx.ui.notify(`Password "${entry.passwordId}" stored in ${PASSWORD_STORE_LABEL}`, "info");
}

async function askValue(ctx: Ctx, vault: string, key: string): Promise<string | undefined> {
  const how = await ctx.ui.select(`Value for ${key}`, ["Type (masked)", "Generate"]);
  if (how === undefined) return undefined;
  if (how !== "Generate") return (await readMasked(ctx, undefined, `Value for ${key} (vault ${vault})`, undefined)) || undefined;
  const format = await ctx.ui.select("Format", [...FORMATS]);
  if (format === undefined) return undefined;
  const raw = (await ctx.ui.input("Length", "32"))?.trim();
  if (raw === undefined) return undefined;
  const len = raw === "" ? 32 : Number(raw);
  if (!Number.isInteger(len) || len < 8 || len > 256) throw new Error("Length must be an integer between 8 and 256");
  return generateValue(format as (typeof FORMATS)[number], len);
}

/** Re-reads the vault, applies the mutation to the current file, writes, refreshes the session copy. */
async function commitKey(ctx: Ctx, session: Session, vault: string, op: Mutation): Promise<void> {
  const entry = (await readConfig(ctx))[vault];
  if (!entry) throw new Error(`Unknown vault "${vault}"`);
  const file = path.resolve(ctx.cwd, entry.file);
  const fileText = await readIfExists(file, "Vault file");
  const { pw, plaintext, header } = await decryptWithStored(entry.passwordId, fileText, vault);
  const next = applyMutation(plaintext, op);
  await writeVaultFile(file, fileText, next, pw, header, vault);
  session.open.set(vault, next);
}

async function flowKey(ctx: Ctx, session: Session, intent: Extract<Intent, { k: `key-${string}` }>): Promise<void> {
  const { vault } = intent;
  if (intent.k === "key-add") {
    const key = (await ctx.ui.input("Key name"))?.trim();
    if (!key) return;
    applyMutation(session.open.get(vault) ?? "", { kind: "add", entries: [{ key, value: "placeholder" }] }); // preflight
    const value = await askValue(ctx, vault, key);
    if (value === undefined) return;
    await commitKey(ctx, session, vault, { kind: "add", entries: [{ key, value }] });
    session.keySel = key;
    ctx.ui.notify(`Added ${key} to "${vault}" (${value.length} chars)`, "info");
  } else if (intent.k === "key-update") {
    const { key } = intent;
    if (!(await ctx.ui.confirm(`Overwrite ${key} in ${vault}?`, "The current value is replaced."))) return;
    const value = await askValue(ctx, vault, key);
    if (value === undefined) return;
    await commitKey(ctx, session, vault, { kind: "update", entries: [{ key, value }] });
    ctx.ui.notify(`Updated ${key} in "${vault}" (${value.length} chars)`, "info");
  } else {
    const { key } = intent;
    if (!(await ctx.ui.confirm(`Delete key ${key} from ${vault}?`, "This removes the key and its value from the vault file."))) return;
    await commitKey(ctx, session, vault, { kind: "delete", keys: [key] });
    session.revealed.delete(revealId(vault, key));
    session.keySel = undefined;
    ctx.ui.notify(`Deleted ${key} from "${vault}"`, "info");
  }
}

async function runIntent(ctx: Ctx, session: Session, rows: VaultRow[], intent: Exclude<Intent, { k: "close" }>): Promise<void> {
  switch (intent.k) {
    case "add":
      return flowAdd(ctx, session);
    case "edit":
      return flowEdit(ctx, session, intent.vault);
    case "remove":
      return flowRemove(ctx, session, intent.vault);
    case "password":
      return flowPassword(ctx, intent.vault);
    case "open": {
      const row = rows.find(r => r.name === intent.vault);
      if (row) return flowOpen(ctx, session, row);
      return;
    }
    default:
      return flowKey(ctx, session, intent);
  }
}

export async function runVaultsScreen(ctx: ExtensionContext): Promise<void> {
  const session: Session = { selected: undefined, focus: "vaults", keySel: undefined, open: new Map(), revealed: new Set() };
  for (;;) {
    const rows = await loadRows(ctx);
    if (!rows) return;
    for (const name of session.open.keys()) if (!rows.some(r => r.name === name)) dropVaultState(session, name);
    if (!rows.some(r => r.name === session.selected)) session.selected = rows[0]?.name;
    if (session.focus === "keys" && !(session.selected && session.open.has(session.selected))) session.focus = "vaults";

    const intent = await showScreen(ctx, session, rows);
    if (intent.k === "close") return;
    try {
      await runIntent(ctx, session, rows, intent);
    } catch (err) {
      ctx.ui.notify(errMsg(err), "error");
    }
  }
}

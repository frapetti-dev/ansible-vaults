import type { AgentToolUpdateCallback, ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import type * as PiTui from "@oh-my-pi/pi-tui";
import type { KeybindingsManager, TUI, Theme } from "@oh-my-pi/pi-tui";
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  pbkdf2Sync,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";

/**
 * `ansible_vault` tool: list / add / update / delete top-level keys of Ansible
 * Vault files declared in `.omp/ansible-vaults.json`. Native TypeScript
 * implementation of the vault 1.1/1.2 AES256 format, so no `ansible-vault`
 * binary is needed. Values never go back to the model; mutations are gated by
 * an in-tool confirmation dialog.
 */

// ---------------------------------------------------------------------------
// Vault crypto (format 1.1 / 1.2, AES256)
// ---------------------------------------------------------------------------

const HEADER_RE = /^\$ANSIBLE_VAULT;(1\.1|1\.2);AES256(;[^\s;]+)?$/;
const HEX_RE = /^(?:[0-9a-fA-F]{2})*$/;

function deriveKeys(password: string, salt: Buffer): { key1: Buffer; key2: Buffer; iv: Buffer } {
  const derived = pbkdf2Sync(password, salt, 10000, 80, "sha256");
  return { key1: derived.subarray(0, 32), key2: derived.subarray(32, 64), iv: derived.subarray(64, 80) };
}

function pkcs7Pad(data: Buffer): Buffer {
  const pad = 16 - (data.length % 16);
  return Buffer.concat([data, Buffer.alloc(pad, pad)]);
}

function pkcs7Unpad(data: Buffer): Buffer {
  const pad = data.length > 0 ? data[data.length - 1]! : 0;
  if (pad < 1 || pad > 16 || pad > data.length) throw new Error("Invalid PKCS7 padding in vault");
  for (let i = data.length - pad; i < data.length; i++) {
    if (data[i] !== pad) throw new Error("Invalid PKCS7 padding in vault");
  }
  return data.subarray(0, data.length - pad);
}

export function decryptVault(fileText: string, password: string, label = "vault"): { plaintext: string; header: string } {
  const lines = fileText.split(/\r?\n/);
  const header = lines[0] ?? "";
  if (!HEADER_RE.test(header)) throw new Error(`Not an ansible-vault 1.1/1.2 AES256 file: ${label}`);

  const bodyHex = lines.slice(1).join("").replace(/\s+/g, "");
  if (!HEX_RE.test(bodyHex)) throw new Error("Malformed vault body");
  const parts = Buffer.from(bodyHex, "hex").toString("ascii").split("\n");
  if (parts.length !== 3 || parts.some(p => !HEX_RE.test(p))) throw new Error("Malformed vault body");

  const salt = Buffer.from(parts[0]!, "hex");
  const hmac = Buffer.from(parts[1]!, "hex");
  const ciphertext = Buffer.from(parts[2]!, "hex");

  const { key1, key2, iv } = deriveKeys(password, salt);
  const expected = createHmac("sha256", key2).update(ciphertext).digest();
  if (expected.length !== hmac.length || !timingSafeEqual(expected, hmac)) {
    throw new Error(`HMAC mismatch for vault "${label}": wrong password or corrupted file`);
  }

  const decipher = createDecipheriv("aes-256-ctr", key1, iv);
  const padded = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return { plaintext: pkcs7Unpad(padded).toString("utf8"), header };
}

export function encryptVault(plaintext: string, password: string, header: string, eol = "\n"): string {
  const salt = randomBytes(32);
  const { key1, key2, iv } = deriveKeys(password, salt);
  const cipher = createCipheriv("aes-256-ctr", key1, iv);
  const ciphertext = Buffer.concat([cipher.update(pkcs7Pad(Buffer.from(plaintext, "utf8"))), cipher.final()]);
  const hmac = createHmac("sha256", key2).update(ciphertext).digest();
  const body = Buffer.from(`${salt.toString("hex")}\n${hmac.toString("hex")}\n${ciphertext.toString("hex")}`, "ascii").toString("hex");
  const wrapped: string[] = [];
  for (let i = 0; i < body.length; i += 80) wrapped.push(body.slice(i, i + 80));
  return `${header}${eol}${wrapped.join(eol)}${eol}`;
}

// ---------------------------------------------------------------------------
// Plaintext YAML handling (line based; untouched lines are preserved)
// ---------------------------------------------------------------------------

export interface KeyBlock {
  key: string;
  /** 0-based line index of the key line */
  start: number;
  /** 0-based exclusive end line index */
  end: number;
}

export type Mutation =
  | { kind: "add" | "update"; entries: { key: string; value: string }[] }
  | { kind: "delete"; keys: string[] };

const KEY_LINE_RE = /^([A-Za-z_][A-Za-z0-9_]*)\s*:(\s|$)/;
const KEY_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

function splitLines(text: string): { lines: string[]; eol: string } {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.split("\n");
  if (eol === "\r\n") {
    for (let i = 0; i < lines.length; i++) if (lines[i]!.endsWith("\r")) lines[i] = lines[i]!.slice(0, -1);
  }
  return { lines, eol };
}

function parseLines(lines: string[]): KeyBlock[] {
  const blocks: KeyBlock[] = [];
  const seen = new Map<string, number>();
  let current: KeyBlock | undefined;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() === "") continue;
    if (line.startsWith(" ") || line.startsWith("\t")) {
      if (!current) throw unsupported(i);
      current.end = i + 1;
      continue;
    }
    if (line.startsWith("#") || /^(---|\.\.\.)\s*$/.test(line)) {
      current = undefined;
      continue;
    }
    const m = KEY_LINE_RE.exec(line);
    if (!m) throw unsupported(i);
    const key = m[1]!;
    const prev = seen.get(key);
    if (prev !== undefined) throw new Error(`Duplicate key "${key}" at lines ${prev + 1} and ${i + 1}`);
    seen.set(key, i);
    current = { key, start: i, end: i + 1 };
    blocks.push(current);
  }
  return blocks;
}

function unsupported(index: number): Error {
  return new Error(`Unsupported top-level YAML at line ${index + 1} (only simple "key: value" mappings are supported)`);
}

export function parseTopLevelKeys(plaintext: string): KeyBlock[] {
  return parseLines(splitLines(plaintext).lines);
}

function serialize(key: string, value: string): string {
  const quoted = JSON.stringify(value);
  return /\{\{|\{%|\{#/.test(value) ? `${key}: !unsafe ${quoted}` : `${key}: ${quoted}`;
}

function checkKeyNames(keys: string[]): void {
  const seen = new Set<string>();
  for (const key of keys) {
    if (!KEY_NAME_RE.test(key)) throw new Error(`Invalid key name "${key}"`);
    if (seen.has(key)) throw new Error(`Key "${key}" given more than once`);
    seen.add(key);
  }
}

export function applyMutation(plaintext: string, op: Mutation): string {
  const { lines, eol } = splitLines(plaintext);
  const blocks = parseLines(lines);
  const byKey = new Map(blocks.map(b => [b.key, b]));
  const keys = op.kind === "delete" ? op.keys : op.entries.map(e => e.key);
  checkKeyNames(keys);

  if (op.kind === "add") {
    const existing = keys.filter(k => byKey.has(k));
    if (existing.length > 0) throw new Error(`Key(s) already exist: ${existing.join(", ")}`);
    let last = lines.length - 1;
    while (last >= 0 && lines[last]!.trim() === "") last--;
    lines.splice(last + 1, 0, ...op.entries.map(e => serialize(e.key, e.value)));
  } else {
    const missing = keys.filter(k => !byKey.has(k));
    if (missing.length > 0) throw new Error(`Key(s) not found: ${missing.join(", ")}`);
    const targets = keys.map(k => byKey.get(k)!).sort((a, b) => b.start - a.start);
    for (const block of targets) {
      const replacement = op.kind === "update" ? [serialize(block.key, op.entries.find(e => e.key === block.key)!.value)] : [];
      lines.splice(block.start, block.end - block.start, ...replacement);
    }
  }

  while (lines.length > 0 && lines[lines.length - 1]!.trim() === "") lines.pop();
  return lines.length === 0 ? "" : lines.join(eol) + eol;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function isEnoent(err: unknown): boolean {
  return typeof err === "object" && err !== null && "code" in err && err.code === "ENOENT";
}

interface VaultConfigEntry {
  file: string;
  passwordFile: string;
  description?: string;
}

const CONFIG_REL = ".omp/ansible-vaults.json";
const VAULT_NAME_RE = /^[A-Za-z0-9_-]+$/;

async function loadConfig(cwd: string): Promise<Record<string, VaultConfigEntry>> {
  const configPath = path.resolve(cwd, CONFIG_REL);
  let raw: string;
  try {
    raw = await fs.readFile(configPath, "utf8");
  } catch (err) {
    if (isEnoent(err)) {
      throw new Error(`Config not found: ${configPath}. Create ${CONFIG_REL} with {"vaults":{...}}.`);
    }
    throw err;
  }
  const invalid = (reason: string) => new Error(`Invalid ${CONFIG_REL}: ${reason}`);
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (err) {
    throw invalid((err as Error).message);
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) throw invalid("expected an object");
  const vaults: unknown = "vaults" in json ? json.vaults : undefined;
  if (typeof vaults !== "object" || vaults === null || Array.isArray(vaults)) throw invalid('"vaults" must be an object');
  const out: Record<string, VaultConfigEntry> = {};
  for (const [name, entry] of Object.entries(vaults)) {
    if (!VAULT_NAME_RE.test(name)) throw invalid(`vault name "${name}" must match ${VAULT_NAME_RE.source}`);
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) throw invalid(`vault "${name}" must be an object`);
    const e = entry as Record<string, unknown>;
    if (typeof e.file !== "string" || e.file === "") throw invalid(`vault "${name}": "file" must be a non-empty string`);
    if (typeof e.passwordFile !== "string" || e.passwordFile === "") {
      throw invalid(`vault "${name}": "passwordFile" must be a non-empty string`);
    }
    if (e.description !== undefined && typeof e.description !== "string") {
      throw invalid(`vault "${name}": "description" must be a string`);
    }
    out[name] = {
      file: e.file,
      passwordFile: e.passwordFile,
      ...(e.description !== undefined ? { description: e.description as string } : {}),
    };
  }
  return out;
}

// ---------------------------------------------------------------------------
// Tool
// ---------------------------------------------------------------------------

type Action = "list_vaults" | "list_keys" | "add" | "update" | "delete";
type Source = "generate" | "prompt" | "file" | "literal";

interface EntryParam {
  key: string;
  source: Source;
  format?: "urlsafe" | "base64" | "hex" | "alnum";
  length?: number;
  path?: string;
  value?: string;
  prompt?: string;
}

interface Params {
  action: Action;
  vault?: string;
  entries?: EntryParam[];
  keys?: string[];
}

const ALLOWED_FIELDS: Record<Source, (keyof EntryParam)[]> = {
  generate: ["format", "length"],
  prompt: ["prompt"],
  file: ["path"],
  literal: ["value"],
};
const SOURCE_FIELDS: (keyof EntryParam)[] = ["format", "length", "path", "value", "prompt"];

function validateParams(p: Params): void {
  if (p.action !== "list_vaults" && !p.vault) throw new Error(`"vault" is required for action "${p.action}"`);
  const mutating = p.action === "add" || p.action === "update";
  if (mutating) {
    if (!p.entries || p.entries.length === 0) throw new Error(`"entries" is required and must be non-empty for action "${p.action}"`);
  } else if (p.entries !== undefined) {
    throw new Error(`"entries" is only valid for add/update`);
  }
  if (p.action === "delete") {
    if (!p.keys || p.keys.length === 0) throw new Error(`"keys" is required and must be non-empty for action "delete"`);
  } else if (p.keys !== undefined) {
    throw new Error(`"keys" is only valid for delete`);
  }
  for (const e of p.entries ?? []) {
    const allowed = ALLOWED_FIELDS[e.source];
    for (const f of SOURCE_FIELDS) {
      if (e[f] !== undefined && !allowed.includes(f)) throw new Error(`Field "${f}" is not valid for source "${e.source}"`);
    }
    if (e.source === "file" && !e.path) throw new Error(`"path" is required for source "file" (key "${e.key}")`);
    if (e.source === "literal" && e.value === undefined) throw new Error(`"value" is required for source "literal" (key "${e.key}")`);
  }
}

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

function generateValue(format: NonNullable<EntryParam["format"]>, n: number): string {
  switch (format) {
    case "urlsafe":
      return randomBytes(n).toString("base64url");
    case "base64":
      return randomBytes(n).toString("base64");
    case "hex":
      return randomBytes(n).toString("hex");
    case "alnum": {
      let s = "";
      for (let i = 0; i < n; i++) s += ALNUM[randomInt(62)];
      return s;
    }
  }
}

function describeEntry(e: EntryParam): string {
  switch (e.source) {
    case "generate":
      return `generate ${e.format ?? "urlsafe"} ${e.length ?? 32}`;
    case "prompt":
      return "prompt";
    case "file":
      return `file ${e.path}`;
    case "literal":
      return `literal ${JSON.stringify(e.value)}`;
  }
}

async function readMasked(
  ctx: ExtensionContext,
  signal: AbortSignal | undefined,
  title: string,
  message: string | undefined,
): Promise<string | undefined> {
  let tuiMod: typeof PiTui;
  try {
    // Dynamic: keeps the pure helpers importable from a plain bun script without resolving host packages.
    tuiMod = await import("@oh-my-pi/pi-tui");
  } catch {
    throw new Error('prompt source unavailable (pi-tui not resolvable); use secret_input + source "file"');
  }
  const { Container, Input, Text } = tuiMod;

  class SecretPrompt {
    #container: InstanceType<typeof Container>;
    #input: InstanceType<typeof Input>;

    constructor(
      private tui: TUI,
      theme: Theme,
      title: string,
      message: string | undefined,
      done: (v: string | undefined) => void,
    ) {
      this.#input = new Input();
      this.#input.mask = true;
      this.#input.prompt = "> ";
      this.#input.onSubmit = (v: string) => done(v);
      this.#input.onEscape = () => done(undefined);

      const children = [new Text(theme.fg("accent", theme.bold(title)), 1, 0)];
      if (message) children.push(new Text(theme.fg("muted", message), 1, 0));
      children.push(this.#input);
      children.push(new Text(theme.fg("muted", "Enter: save · Esc: cancel · the value is never shown to the model"), 1, 0));

      this.#container = new Container();
      for (const child of children) this.#container.children.push(child);
    }

    render(width: number): readonly string[] {
      return this.#container.render(width);
    }

    invalidate(): void {
      this.#container.invalidate?.();
    }

    handleInput(data: string): void {
      this.#input.handleInput(data);
      this.tui.requestRender();
    }

    get focused(): boolean {
      return this.#input.focused;
    }

    set focused(value: boolean) {
      this.#input.focused = value;
    }
  }

  return ctx.ui.custom<string | undefined>(
    (tui: TUI, theme: Theme, _kb: KeybindingsManager, done: (v: string | undefined) => void) =>
      new SecretPrompt(tui, theme, title, message, done),
    { overlay: true, ...(signal ? { signal } : {}) },
  );
}

async function resolveValue(
  e: EntryParam,
  vault: string,
  ctx: ExtensionContext,
  signal: AbortSignal | undefined,
): Promise<string> {
  switch (e.source) {
    case "generate":
      return generateValue(e.format ?? "urlsafe", e.length ?? 32);
    case "file": {
      const abs = path.resolve(ctx.cwd, e.path!);
      let text: string;
      try {
        text = await fs.readFile(abs, "utf8");
      } catch (err) {
        if (isEnoent(err)) throw new Error(`Value file not found: ${abs}`);
        throw err;
      }
      text = text.replace(/\r?\n$/, "");
      if (text === "") throw new Error(`Value file is empty: ${abs}`);
      return text;
    }
    case "literal":
      if (e.value === "") throw new Error(`Literal value for "${e.key}" is empty`);
      return e.value!;
    case "prompt": {
      const result = await readMasked(ctx, signal, `Value for ${e.key} (vault ${vault})`, e.prompt);
      const value = result?.trim() ?? "";
      if (value === "") throw new Error(`User cancelled value entry for "${e.key}"; nothing was written.`);
      return value;
    }
  }
}

async function readIfExists(file: string, what: string): Promise<string> {
  try {
    return await fs.readFile(file, "utf8");
  } catch (err) {
    if (isEnoent(err)) throw new Error(`${what} not found: ${file}`);
    throw err;
  }
}

async function exists(file: string): Promise<boolean> {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

function text(t: string, details: unknown) {
  return { content: [{ type: "text" as const, text: t }], details };
}

export default function ansibleVault(pi: ExtensionAPI) {
  pi.setLabel("Ansible vault");
  const z = pi.zod;

  pi.registerTool({
    name: "ansible_vault",
    label: "Ansible Vault",
    loadMode: "essential",
    approval: "read",
    description:
      'List, add, update and delete top-level keys in Ansible Vault files declared in .omp/ansible-vaults.json. Actions: list_vaults (configured vaults, no decryption), list_keys (key names only), add / update / delete. Secret VALUES ARE NEVER RETURNED to you; only key names and lengths. add/update/delete show a user confirmation dialog listing the exact keys — the user approving it is the authorization; if denied, nothing is written. Operations are atomic: all keys are applied or none. Value sources: generate (random, for secrets), prompt (user types it in a masked prompt), file (read from a path, e.g. from secret_input), literal (NON-SECRET values only, e.g. a domain — it is visible in chat). add fails if a key exists; update/delete fail if a key is missing.',
    parameters: z.object({
      action: z.enum(["list_vaults", "list_keys", "add", "update", "delete"]),
      vault: z.string().optional().describe("Vault name from .omp/ansible-vaults.json; required except for list_vaults"),
      entries: z
        .array(
          z.object({
            key: z.string(),
            source: z.enum(["generate", "prompt", "file", "literal"]),
            format: z.enum(["urlsafe", "base64", "hex", "alnum"]).optional().describe("generate only; default urlsafe"),
            length: z
              .number()
              .int()
              .min(8)
              .max(256)
              .optional()
              .describe("generate only; random bytes (urlsafe/base64/hex) or characters (alnum); default 32"),
            path: z.string().optional().describe("file only; path relative to cwd"),
            value: z
              .string()
              .optional()
              .describe("literal only; NON-SECRET values only (e.g. a domain) — it is visible in chat"),
            prompt: z.string().optional().describe("prompt only; hint shown to the user"),
          }),
        )
        .optional()
        .describe("add/update: one or more keys, applied atomically"),
      keys: z.array(z.string()).optional().describe("delete: keys to remove, applied atomically"),
    }),
    async execute(
      _toolCallId: string,
      params: Params,
      signal: AbortSignal | undefined,
      _onUpdate: AgentToolUpdateCallback | undefined,
      ctx: ExtensionContext,
    ) {
      validateParams(params);
      const config = await loadConfig(ctx.cwd);

      if (params.action === "list_vaults") {
        const vaults = await Promise.all(
          Object.entries(config).map(async ([name, v]) => {
            const file = path.resolve(ctx.cwd, v.file);
            const passwordFile = path.resolve(ctx.cwd, v.passwordFile);
            let header: string | null = null;
            try {
              header = (await fs.readFile(file, "utf8")).split(/\r?\n/, 1)[0] ?? null;
            } catch {
              header = null;
            }
            return {
              name,
              description: v.description ?? null,
              file: v.file,
              passwordFile: v.passwordFile,
              fileExists: header !== null,
              passwordFileExists: await exists(passwordFile),
              header,
            };
          }),
        );
        return text(JSON.stringify({ vaults }, null, 2), { action: "list_vaults", vaults });
      }

      const vaultName = params.vault!;
      const entry = config[vaultName];
      if (!entry) throw new Error(`Unknown vault "${vaultName}". Available: ${Object.keys(config).join(", ")}`);
      const vaultFile = path.resolve(ctx.cwd, entry.file);
      const passwordFile = path.resolve(ctx.cwd, entry.passwordFile);

      const fileText = await readIfExists(vaultFile, "Vault file");
      const password = (await readIfExists(passwordFile, "Password file")).trim();
      if (password === "") throw new Error(`Password file is empty: ${passwordFile}`);

      const { plaintext, header } = decryptVault(fileText, password, vaultName);

      if (params.action === "list_keys") {
        const names = parseTopLevelKeys(plaintext).map(b => b.key);
        return text(JSON.stringify({ vault: vaultName, keys: names, count: names.length }, null, 2), {
          action: "list_keys",
          vault: vaultName,
          count: names.length,
        });
      }

      // Mutations
      const action = params.action;
      const entries = params.entries ?? [];
      const keyList = action === "delete" ? params.keys! : entries.map(e => e.key);

      // Preflight with placeholder values: parse / existence / duplicate errors surface before the dialog.
      const placeholder: Mutation =
        action === "delete"
          ? { kind: "delete", keys: keyList }
          : { kind: action as "add" | "update", entries: entries.map(e => ({ key: e.key, value: "placeholder" })) };
      applyMutation(plaintext, placeholder);

      if (entries.some(e => e.source === "prompt") && ctx.mode !== "tui") {
        throw new Error("prompt source needs the interactive TUI");
      }

      // Confirmation
      if (!ctx.hasUI) {
        throw new Error(
          "ansible_vault add/update/delete needs an interactive UI to confirm; ask the user to run it from the TUI.",
        );
      }
      const lines =
        action === "delete"
          ? keyList.map(k => `  ${k}  ←  delete`)
          : entries.map(e => `  ${e.key}  ←  ${describeEntry(e)}`);
      const confirmed = await ctx.ui.confirm(
        `Ansible vault ${action}: ${vaultName}`,
        [...lines, `File: ${entry.file}`].join("\n"),
      );
      if (!confirmed) throw new Error(`User denied ${action} on vault "${vaultName}"; nothing was written.`);

      // Resolve all values before any write.
      const resolved: { key: string; value: string; entry: EntryParam }[] = [];
      for (const e of entries) resolved.push({ key: e.key, value: await resolveValue(e, vaultName, ctx, signal), entry: e });

      const finalOp: Mutation =
        action === "delete"
          ? { kind: "delete", keys: keyList }
          : { kind: action as "add" | "update", entries: resolved.map(r => ({ key: r.key, value: r.value })) };
      const newPlaintext = applyMutation(plaintext, finalOp);

      const eol = fileText.includes("\r\n") ? "\r\n" : "\n";
      const newText = encryptVault(newPlaintext, password, header, eol);
      if (decryptVault(newText, password, vaultName).plaintext !== newPlaintext) {
        throw new Error("Round-trip verification failed; vault not written");
      }

      const tmp = path.join(path.dirname(vaultFile), `.${path.basename(vaultFile)}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`);
      try {
        await fs.writeFile(tmp, newText, "utf8");
        await fs.rename(tmp, vaultFile);
      } catch (err) {
        await fs.rm(tmp, { force: true });
        throw err;
      }

      const summary =
        action === "delete"
          ? keyList.map(k => `delete ${k}`)
          : resolved.map(r => {
              const src = r.entry.source === "generate" ? `generate ${r.entry.format ?? "urlsafe"}` : r.entry.source;
              return `${action} ${r.key} (${src}, ${r.value.length} chars)`;
            });
      return text([...summary, `vault: ${vaultName}`, `file: ${entry.file}`].join("\n"), {
        vault: vaultName,
        action,
        keys:
          action === "delete"
            ? keyList.map(key => ({ key, source: "delete" }))
            : resolved.map(r => ({ key: r.key, source: r.entry.source, length: r.value.length })),
      });
    },
  });
}

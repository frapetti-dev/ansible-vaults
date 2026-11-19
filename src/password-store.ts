import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";

/**
 * OS-backed storage for vault passwords. Never a readable file.
 * - win32: AES-GCM blob sealed with a key derived from a Windows Hello signature; only ciphertext is stored.
 * - darwin: keychain item that trusts no app, so every read raises an OS dialog.
 * - linux: Secret Service (weaker: no per-read prompt).
 */

const SERVICE = "ansible-vaults";
const platform = process.platform;

export const PASSWORD_STORE_LABEL: string =
  platform === "win32"
    ? "Windows Hello"
    : platform === "darwin"
      ? "macOS keychain"
      : platform === "linux"
        ? "Secret Service (no unlock prompt)"
        : "unsupported";

const notStored = (id: string) =>
  new Error(`Vault password "${id}" is not stored; run ansible_vault set_password on a vault that uses it`);

function unsupported(): Error {
  return new Error(`Unsupported platform "${platform}" for the vault password store`);
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

const HELLO_PS = String.raw`$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Security.Credentials.KeyCredentialManager,Windows.Security.Credentials,ContentType=WindowsRuntime]
$null = [Windows.Security.Cryptography.CryptographicBuffer,Windows.Security.Cryptography,ContentType=WindowsRuntime]
$null = [Windows.Storage.Streams.IBuffer,Windows.Storage.Streams,ContentType=WindowsRuntime]
$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation${"`"}1' }
function Await($op, [Type]$t) { $task = $asTask.MakeGenericMethod($t).Invoke($null, @($op)); $task.Wait(); $task.Result }
$KCM = [Windows.Security.Credentials.KeyCredentialManager]
$RR = [Windows.Security.Credentials.KeyCredentialRetrievalResult]
$r = Await ($KCM::OpenAsync('ansible-vaults')) $RR
if ($r.Status -eq 'NotFound' -and $env:AV_MODE -eq 'create') { $r = Await ($KCM::RequestCreateAsync('ansible-vaults', 'FailIfExists')) $RR }
if ($r.Status -ne 'Success') { [Console]::Error.Write('open:' + $r.Status); exit 3 }
$WRB = [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]
$buf = $WRB::AsBuffer([Convert]::FromBase64String($env:AV_CHALLENGE))
$s = Await ($r.Credential.RequestSignAsync($buf)) ([Windows.Security.Credentials.KeyCredentialOperationResult])
if ($s.Status -ne 'Success') { [Console]::Error.Write('sign:' + $s.Status); exit 4 }
$toArray = $WRB.GetMethod('ToArray', [Type[]]@([Windows.Storage.Streams.IBuffer]))
[Console]::Out.Write([Convert]::ToBase64String($toArray.Invoke($null, @($s.Result))))
`;

// RSASSA-PKCS1-v1_5 signatures are deterministic, so the same challenge always yields the same key; the TPM key never leaves Hello.
async function helloSign(challenge: Buffer, mode: "create" | "open"): Promise<Buffer> {
  const proc = Bun.spawn(
    [
      "powershell.exe",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-EncodedCommand",
      Buffer.from(HELLO_PS, "utf16le").toString("base64"),
    ],
    {
      env: { ...process.env, AV_MODE: mode, AV_CHALLENGE: challenge.toString("base64") },
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  const [out, err, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code === 0) return Buffer.from(out.trim(), "base64");
  const e = err.trim();
  if (e === "open:NotFound") {
    throw new Error(`Windows Hello key "${SERVICE}" not found (PIN reset or new profile?); run set_password again`);
  }
  if (e.endsWith(":UserCanceled")) throw new Error("Windows Hello unlock cancelled");
  if (e.endsWith(":NotSupported") || e === "open:SecurityDeviceLocked") {
    throw new Error(`Windows Hello is not available: ${e}`);
  }
  throw new Error(`Windows Hello failed: ${e}`);
}

function helloKey(id: string, sig: Buffer): Buffer {
  const info = `ansible-vaults/v1/${id}`;
  return Buffer.from(hkdfSync("sha256", sig, Buffer.alloc(0), info, 32));
}

const helloChallenge = (id: string) => createHash("sha256").update(`ansible-vaults/v1/${id}`).digest();

async function winStore(id: string, password: string): Promise<void> {
  const key = helloKey(id, await helloSign(helloChallenge(id), "create"));
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(id));
  const ct = Buffer.concat([c.update(password, "utf8"), c.final()]);
  const blob = "v1:" + Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64");
  await Bun.secrets.set({ service: SERVICE, name: id, value: blob });
}

async function winLoad(id: string): Promise<string> {
  const blob = await Bun.secrets.get({ service: SERVICE, name: id });
  if (blob === null) throw notStored(id);
  const key = helloKey(id, await helloSign(helloChallenge(id), "open"));
  const bad = () =>
    new Error(`Sealed vault password "${id}" cannot be decrypted (Windows Hello key changed?); run set_password again`);
  if (!blob.startsWith("v1:")) throw bad();
  const raw = Buffer.from(blob.slice(3), "base64");
  try {
    const d = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
    d.setAAD(Buffer.from(id));
    d.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString("utf8");
  } catch {
    throw bad();
  }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

async function security(args: string[], stdin?: string): Promise<{ code: number; out: string; err: string }> {
  const proc = Bun.spawn(["security", ...args], {
    stdin: stdin === undefined ? "ignore" : new Blob([stdin]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [out, err, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, out, err };
}

async function macStore(id: string, password: string): Promise<void> {
  await security(["delete-generic-password", "-s", SERVICE, "-a", id]); // exit 44 = not found, fine
  // -i keeps the password out of argv; -T "" trusts no application.
  const r = await security(
    ["-i"],
    `add-generic-password -s ${SERVICE} -a ${id} -T "" -X ${Buffer.from(password, "utf8").toString("hex")}\n`,
  );
  if (r.code !== 0) throw new Error(`macOS keychain write failed: ${r.err.trim()}`);
}

async function macIsStored(id: string): Promise<boolean> {
  const r = await security(["find-generic-password", "-s", SERVICE, "-a", id]);
  if (r.code === 0) return true;
  if (r.code === 44) return false;
  throw new Error(`macOS keychain lookup failed: ${r.err.trim()}`);
}

async function macLoad(id: string): Promise<string> {
  const r = await security(["find-generic-password", "-s", SERVICE, "-a", id, "-w"]);
  if (r.code === 44) throw notStored(id);
  if (r.code !== 0) throw new Error("macOS keychain access denied or cancelled");
  return r.out.replace(/\n$/, "");
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

async function secretService<T>(op: () => Promise<T>): Promise<T> {
  try {
    return await op();
  } catch (err) {
    throw new Error(`Secret Service unavailable: ${(err as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** MUST NOT prompt. */
export async function isVaultPasswordStored(id: string): Promise<boolean> {
  if (platform === "win32") return (await Bun.secrets.get({ service: SERVICE, name: id })) !== null;
  if (platform === "darwin") return macIsStored(id);
  if (platform === "linux") return secretService(async () => (await Bun.secrets.get({ service: SERVICE, name: id })) !== null);
  throw unsupported();
}

/** May prompt; throws if not stored. */
export async function loadVaultPassword(id: string): Promise<string> {
  if (platform === "win32") return winLoad(id);
  if (platform === "darwin") return macLoad(id);
  if (platform === "linux") {
    const v = await secretService(() => Bun.secrets.get({ service: SERVICE, name: id }));
    if (v === null) throw notStored(id);
    return v;
  }
  throw unsupported();
}

/** Overwrites. */
export async function storeVaultPassword(id: string, password: string): Promise<void> {
  if (platform === "win32") return winStore(id, password);
  if (platform === "darwin") return macStore(id, password);
  if (platform === "linux") return secretService(() => Bun.secrets.set({ service: SERVICE, name: id, value: password }));
  throw unsupported();
}

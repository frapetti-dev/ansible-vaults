import { expect, test } from "bun:test";
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import type { UiNode } from "@oh-my-pi/pi-tui";
import { readMasked } from "../src/ansible-vault.ts";

const key = (id: string, text?: string) => ({ id, text, kind: "press", raw: "" }) as never;

function run(keys: [string, string?][]) {
  const ctx = {
    ui: {
      custom: (factory: (...a: unknown[]) => UiNode) =>
        new Promise<string | undefined>(resolve => {
          const root = factory({ requestRender() {} }, {}, {}, resolve);
          for (const [id, text] of keys) root.handlers.onKey!(key(id, text));
        }),
    },
  } as unknown as ExtensionContext;
  return readMasked(ctx, undefined, "T", undefined);
}

test("readMasked: typed keys then enter returns the value", async () => {
  expect(await run([["a", "a"], ["b", "b"], ["enter"]])).toBe("ab");
});

test("readMasked: escape cancels", async () => {
  expect(await run([["a", "a"], ["escape"]])).toBeUndefined();
});

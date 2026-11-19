/**
 * Dependency-light helpers for building Tern Surface Protocol (TSP) nodes.
 * Types only from pi-wire; the one value import is `matchesKey` from pi-tui.
 */
import type { DescribeContext, NativeChild, NativeNode } from "@oh-my-pi/pi-tui";
import { matchesKey } from "@oh-my-pi/pi-tui";
import type { TspKind, TspProps, TspSpan } from "@oh-my-pi/pi-wire";

/** Build a node: `{ k, p, c, key }`. */
export function n<K extends TspKind>(
	k: K,
	p?: TspProps<K>,
	c?: readonly NativeChild[],
	key?: string,
): NativeNode {
	return { k, p, c, key } as unknown as NativeNode;
}

/** A `text` node from a plain string or spans. */
export function txt(s: string | readonly TspSpan[], p: TspProps<"text"> = {}): NativeNode {
	return typeof s === "string" ? n("text", { ...p, text: s }) : n("text", { ...p, spans: s });
}

/**
 * Body prose. Free-form `text`/`md` render in monospace unless a role says otherwise;
 * `omp.advisor.note` is a Tern-internal role that draws compact sans text (no box, no padding).
 */
export function prose(s: string | readonly TspSpan[], p: TspProps<"text"> = {}): NativeNode {
	return txt(s, { role: "omp.advisor.note", ...p });
}

/** Short sans heading for a dialog (`omp.sheet.head`: 14px, weight 600); replaces monospace card/section heads. */
export function heading(s: string): NativeNode {
	return txt(s, { role: "omp.sheet.head" });
}

/**
 * Dialog content inset from the overlay frame. TSP has no padding prop on `col`/`row`, an overlay
 * role does not pad, and a head-less `card` draws a ring, so padding is built from spacers.
 */
export function framed(kids: readonly NativeChild[], gap: "sm" | "md" | "lg"): NativeNode {
	const side = (key: string) => n("spacer", { min: { w: "2ch" } }, undefined, key);
	return n(
		"col",
		{ gap: "none" },
		[
			n("spacer", { size: "sm" }, undefined, "top"),
			n("row", { align: "start" }, [side("left"), n("col", { gap, grow: 1 }, kids, "content"), side("right")], "inset"),
			n("spacer", { size: "sm" }, undefined, "bottom"),
		],
		"frame",
	);
}

/** Native button: a `row` with role `omp.btn`; a click arrives as `{type:"action", act}`. */
export function button(label: string, act: string, keys?: string): NativeNode {
	const children: NativeChild[] = [txt(label)];
	if (keys) children.push(n("kbd", { keys: keys.split("+") }));
	return n(
		"row",
		{ role: "omp.btn", gap: "xs", align: "center", actions: { click: act }, title: label },
		children,
		act,
	);
}

/** Action bar; `null` entries become a growing spacer. */
export function bar(buttons: readonly (NativeNode | null)[], key = "actions"): NativeNode {
	const children = buttons.map(b => b ?? n("spacer", { grow: 1 }));
	return n("row", { role: "omp.actions", gap: "sm", align: "center" }, children, key);
}

/** `build()` when the terminal supports `kind`, else a muted notice. */
export function guard(cx: DescribeContext, kind: TspKind, build: () => NativeNode): NativeNode {
	return cx.supports(kind) ? build() : txt([{ t: `${kind}: not supported by this Tern build`, s: "muted" }]);
}

/** Truncate plain text to `width` cells with an ellipsis (ANSI fallbacks use plain text only). */
export function fit(line: string, width: number): string {
	if (width <= 0) return "";
	return line.length <= width ? line : `${line.slice(0, Math.max(0, width - 1))}…`;
}

export function isKey(data: string, id: string): boolean {
	return matchesKey(data, id as never);
}

export function isClose(data: string): boolean {
	return isKey(data, "escape") || data === "q";
}

/** Last segment of an event key path (`"a/b/tabs"` -> `"tabs"`). */
export function leafKey(path: string): string {
	return path.slice(path.lastIndexOf("/") + 1);
}

/**
 * Memoize `build` on a list of dependencies: returns the same node object
 * while every dependency is unchanged (the describe contract asks for this).
 */
export class Memo {
	#deps: readonly unknown[] | undefined;
	#value: NativeNode | undefined;
	get(deps: readonly unknown[], build: () => NativeNode): NativeNode {
		const d = this.#deps;
		if (this.#value && d && d.length === deps.length && d.every((v, i) => Object.is(v, deps[i]))) {
			return this.#value;
		}
		this.#deps = deps;
		this.#value = build();
		return this.#value;
	}
}

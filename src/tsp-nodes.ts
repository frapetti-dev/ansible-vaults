/**
 * Dependency-light helpers for building TSP nodes as pi-tui nodes, plus `mount`, the bridge to `ctx.ui.custom`.
 * Value imports from the @oh-my-pi/pi-tui root only.
 */
import { jsx, signal, type JSXNode, type KeyEvent, type UiEvent } from "@oh-my-pi/pi-tui";
import type { TspKind, TspProps, TspSpan } from "@oh-my-pi/pi-wire";

/** A focused view: its tree plus its input handlers. */
export interface View {
	describe(): JSXNode;
	handleKey(key: KeyEvent): void;
	handlePaste?(text: string): void;
	handleEvent?(e: UiEvent): void;
}

/** Root node for ctx.ui.custom: rebuilds `describe()` whenever `refresh` runs; routes keys/paste/events to the view. */
export function mount(build: (refresh: () => void) => View): JSXNode {
	const tick = signal(0);
	const view = build(() => tick.update(v => v + 1));
	return jsx("col", {
		children: () => {
			tick();
			return view.describe();
		},
		onKey: (key: KeyEvent) => {
			if (key.kind === "release") return false;
			view.handleKey(key);
			return true;
		},
		onPaste: (p: { text: string }) => {
			view.handlePaste?.(p.text);
			return true;
		},
		onEvent: (e: UiEvent) => view.handleEvent?.(e),
	});
}

/** Build a node. */
export function n<K extends TspKind>(k: K, p?: TspProps<K>, c?: readonly JSXNode[], key?: string): JSXNode {
	return jsx(k, c === undefined ? { ...p } : { ...p, children: c }, key) as JSXNode;
}

/** A `text` node from a plain string or spans. */
export function txt(s: string | readonly TspSpan[], p: TspProps<"text"> = {}): JSXNode {
	return typeof s === "string" ? n("text", { ...p, text: s }) : n("text", { ...p, spans: s });
}

/**
 * Body prose. Free-form `text`/`md` render in monospace unless a role says otherwise;
 * `omp.advisor.note` is a Tern-internal role that draws compact sans text (no box, no padding).
 */
export function prose(s: string | readonly TspSpan[], p: TspProps<"text"> = {}): JSXNode {
	return txt(s, { role: "omp.advisor.note", ...p });
}

/** Short sans heading for a dialog (`omp.sheet.head`: 14px, weight 600); replaces monospace card/section heads. */
export function heading(s: string): JSXNode {
	return txt(s, { role: "omp.sheet.head" });
}

/**
 * Dialog content inset from the overlay frame. TSP has no padding prop on `col`/`row`, an overlay
 * role does not pad, and a head-less `card` draws a ring, so padding is built from spacers.
 */
export function framed(kids: readonly JSXNode[], gap: "sm" | "md" | "lg"): JSXNode {
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
export function button(label: string, act: string, keys?: string): JSXNode {
	const children: JSXNode[] = [txt(label)];
	if (keys) children.push(n("kbd", { keys: keys.split("+") }));
	return n(
		"row",
		{ role: "omp.btn", gap: "xs", align: "center", actions: { click: act }, title: label },
		children,
		act,
	);
}

/** Action bar; `null` entries become a growing spacer. */
export function bar(buttons: readonly (JSXNode | null)[], key = "actions"): JSXNode {
	const children = buttons.map(b => b ?? n("spacer", { grow: 1 }));
	return n("row", { role: "omp.actions", gap: "sm", align: "center" }, children, key);
}

/** Truncate plain text to `width` cells with an ellipsis (ANSI fallbacks use plain text only). */
export function fit(line: string, width: number): string {
	if (width <= 0) return "";
	return line.length <= width ? line : `${line.slice(0, Math.max(0, width - 1))}…`;
}

/** Last segment of an event key path (`"a/b/tabs"` -> `"tabs"`). */
export function leafKey(path: string): string {
	return path.slice(path.lastIndexOf("/") + 1);
}

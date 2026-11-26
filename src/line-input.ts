/** Single-line text editing state for pane forms and the secret dialog. */
import type { JSXNode, KeyEvent } from "@oh-my-pi/pi-tui";
import { n } from "./tsp-nodes.ts";

export class LineInput {
	value: string;
	cursor: number;

	constructor(
		initial = "",
		private readonly opts: { masked?: boolean } = {},
	) {
		this.value = initial;
		this.cursor = initial.length;
	}

	/** Returns true when the key was consumed. */
	handleKey(key: KeyEvent): boolean {
		const id = key.id;
		if (id === "backspace") {
			if (this.cursor > 0) {
				this.value = this.value.slice(0, this.cursor - 1) + this.value.slice(this.cursor);
				this.cursor--;
			}
			return true;
		}
		if (id === "delete") {
			this.value = this.value.slice(0, this.cursor) + this.value.slice(this.cursor + 1);
			return true;
		}
		if (id === "left") {
			this.cursor = Math.max(0, this.cursor - 1);
			return true;
		}
		if (id === "right") {
			this.cursor = Math.min(this.value.length, this.cursor + 1);
			return true;
		}
		if (id === "home") {
			this.cursor = 0;
			return true;
		}
		if (id === "end") {
			this.cursor = this.value.length;
			return true;
		}
		if (id === "ctrl+u") {
			this.value = "";
			this.cursor = 0;
			return true;
		}
		const text = key.text?.replace(/[\r\n]/g, "");
		if (text && !/[\x00-\x1f\x7f]/.test(text) && !/^(ctrl|alt|super)\+/.test(id)) {
			this.paste(text);
			return true;
		}
		return false;
	}

	paste(text: string): void {
		const flat = text.replace(/\r?\n/g, "");
		this.value = this.value.slice(0, this.cursor) + flat + this.value.slice(this.cursor);
		this.cursor += flat.length;
	}

	display(): string {
		return this.opts.masked ? "•".repeat(this.value.length) : this.value;
	}

	node(p: { key: string; focused: boolean; placeholder?: string }): JSXNode {
		return n(
			"input",
			{ text: this.display(), cursor: p.focused ? this.cursor : undefined, placeholder: p.placeholder, readonly: !p.focused },
			undefined,
			p.key,
		);
	}
}

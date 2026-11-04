import { ApiError, revokeSecret } from "../api.ts";
import { el } from "../dom.ts";
import { formatRelative, formatUTC } from "../format.ts";
import { icon } from "../icons.ts";
import type { ReceiptState } from "../types.ts";
import {
  PRODUCT,
  copyButton,
  notice,
  page,
  recordRow,
} from "./shared.ts";

export interface ResultInput {
  secretId: string;
  receiptToken: string;
  shareUrl: string;
  receiptUrl: string;
  expiresAt: number;
  receiptExpiresAt: number;
  passphraseUsed: boolean;
}

export function renderResult(main: HTMLElement, result: ResultInput): void {
  document.title = `Link created — ${PRODUCT}`;

  const column = page();
  const head = el("header", "page-head result-head");
  head.append(
    el("h1", "display", "Your link is ready. It works once."),
    el(
      "p",
      "lede",
      "Send the whole link. Everything after # is the key, and it is never sent.",
    ),
  );

  const col = el("div", "col");
  const rail = el("aside", "rail");
  col.appendChild(head);

  if (result.passphraseUsed) {
    col.appendChild(
      notice(
        "info",
        "Send the passphrase separately. ",
        "The link alone will not open it. Two channels, two messages.",
        "key",
      ),
    );
  }

  const share = el("section", "share");
  const shareInput = el("textarea", "share-link");
  shareInput.id = "share-url";
  shareInput.rows = 3;
  shareInput.readOnly = true;
  shareInput.spellcheck = false;
  shareInput.setAttribute("aria-label", "Share link");
  shareInput.value = result.shareUrl;

  const shareActions = el("div", "share-actions");
  const receiptButton = el("a", "btn btn-quiet");
  receiptButton.href = result.receiptUrl;
  receiptButton.target = "_blank";
  receiptButton.rel = "noopener noreferrer";
  const receiptIcon = el("span", "btn-icon");
  receiptIcon.appendChild(icon("radar", 15));
  receiptButton.append(receiptIcon, el("span", "", "Open receipt"));
  shareActions.append(
    copyButton(() => shareInput.value, "Copy link", "btn btn-primary"),
    el("span", "spacer"),
    receiptButton,
  );
  const receiptInput = el("textarea", "receipt-link");
  receiptInput.rows = 2;
  receiptInput.readOnly = true;
  receiptInput.spellcheck = false;
  receiptInput.setAttribute("aria-label", "Receipt link");
  receiptInput.value = result.receiptUrl;
  const receiptLine = el("div", "receipt-line");
  receiptLine.append(
    el("span", "receipt-label", "Receipt link — keep this to check the open"),
    receiptInput,
  );
  share.append(shareInput, shareActions, receiptLine);
  col.appendChild(share);

  const meta = el("div", "meta-list");
  meta.append(
    recordRow("Expires", formatUTC(result.expiresAt)),
    recordRow("Expires in", formatRelative(result.expiresAt)),
    recordRow("Receipt until", formatUTC(result.receiptExpiresAt)),
    recordRow("Reads left", "1"),
  );
  rail.appendChild(meta);

  const dangerZone = el("section", "danger-zone");
  showRevokeIdle(dangerZone, result, shareInput);
  rail.appendChild(dangerZone);

  const again = el("a", "btn btn-quiet", "Create another secret");
  again.href = "/";
  again.style.marginTop = "1.5rem";
  again.style.marginLeft = "0";
  col.appendChild(again);

  const split = el("div", "split");
  split.append(col, rail);
  column.appendChild(split);
  main.replaceChildren(column);

  window.addEventListener(
    "pagehide",
    () => {
      shareInput.value = "";
      receiptInput.value = "";
    },
    { once: true },
  );
}

function showRevokeIdle(
  block: HTMLElement,
  result: ResultInput,
  shareInput: HTMLTextAreaElement,
): void {
  const header = el("div");
  header.append(
    el("p", "field-label", "Burn before it is read"),
    el(
      "p",
      "note",
      "Destroying the link now means the recipient cannot open it. Your receipt records that it happened.",
    ),
  );
  const button = el("button", "btn btn-danger", "Burn it now");
  button.type = "button";
  button.addEventListener("click", () => showRevokeConfirm(block, result, shareInput));
  block.replaceChildren(header, button);
}

function showRevokeConfirm(
  block: HTMLElement,
  result: ResultInput,
  shareInput: HTMLTextAreaElement,
): void {
  const copy = el(
    "p",
    "note note--danger",
    "Burn this link? The recipient will not be able to open it, and this cannot be undone.",
  );
  const row = el("div", "actions");
  const burn = el("button", "btn btn-danger", "Burn it");
  burn.type = "button";
  const keep = el("button", "btn btn-ghost", "Keep link");
  keep.type = "button";
  keep.addEventListener("click", () => showRevokeIdle(block, result, shareInput));
  burn.addEventListener("click", () => {
    void revoke(block, result, shareInput, burn, keep);
  });
  row.append(burn, keep);
  block.replaceChildren(copy, row);
}

async function revoke(
  block: HTMLElement,
  result: ResultInput,
  shareInput: HTMLTextAreaElement,
  burn: HTMLButtonElement,
  keep: HTMLButtonElement,
): Promise<void> {
  burn.disabled = true;
  keep.disabled = true;
  burn.textContent = "Burning…";
  try {
    const response = await revokeSecret(result.secretId, result.receiptToken);
    shareInput.value = "";
    block.replaceChildren(
      terminalNotice(response.state, response.revokedAt),
    );
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      block.replaceChildren(
        notice(
          "danger",
          "Receipt no longer available",
          "The receipt retention window has ended, so this link can no longer be revoked from here. It will expire on its own.",
          "alert",
        ),
      );
      return;
    }
    burn.disabled = false;
    keep.disabled = false;
    burn.textContent = "Burn it";
    block.prepend(
      notice(
        "danger",
        "The link was not burned",
        "The burn was not confirmed. Check your connection and try again; the link is still live.",
        "alert",
      ),
    );
  }
}

function terminalNotice(state: ReceiptState, revokedAt?: number): HTMLElement {
  if (state === "revoked") {
    return notice(
      "info",
      "Link burned",
      `The unread copy was destroyed${revokedAt ? ` at ${formatUTC(revokedAt)}` : ""}. The recipient will see that it is unavailable.`,
      "eyeOff",
    );
  }
  if (state === "burned") {
    return notice(
      "info",
      "Already burned",
      "The recipient already opened this secret. There is nothing left to revoke.",
      "check",
    );
  }
  if (state === "expired") {
    return notice(
      "info",
      "Already expired",
      "The expiry time passed before the secret was read. There is nothing left to revoke.",
      "clock",
    );
  }
  return notice(
    "info",
    "Nothing to revoke",
    "The secret is no longer available.",
    "shield",
  );
}

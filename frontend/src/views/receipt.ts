import { ApiError, fetchReceipt } from "../api.ts";
import { base64urlDecode, base64urlEncode, wipe } from "../crypto.ts";
import { el } from "../dom.ts";
import { formatUTC } from "../format.ts";
import type { ReceiptEvent, ReceiptEventType, ReceiptView } from "../types.ts";
import { PRODUCT, errorView, page } from "./shared.ts";

// Fast while the recipient is likely mid-flow, then a slow trickle: a sender
// tab left open for an hour costs ~114 requests instead of 1,800.
const POLL_MS = 2_000;

const EVENT_COPY: Record<
  ReceiptEventType,
  { label: string; detail: string }
> = {
  created: {
    label: "Link created",
    detail: "The secret was encrypted in the sender's browser.",
  },
  link_opened: {
    label: "Link opened",
    detail: "The first confirmation-screen load. No secret was sent.",
  },
  decrypt_attempted: {
    label: "Reveal confirmed",
    detail: "A human confirmed the reveal.",
  },
  decrypted: {
    label: "Secret decrypted",
    detail: "AES-GCM authentication succeeded in the recipient's browser.",
  },
  burned: {
    label: "Record burned",
    detail: "The in-memory copy was removed.",
  },
  expired: {
    label: "Expired unread",
    detail: "The time limit elapsed before a reveal.",
  },
  revoked: {
    label: "Revoked by the sender",
    detail: "The sender destroyed the record before it was opened.",
  },
};

export function renderReceipt(main: HTMLElement, id: string): void {
  document.title = `Receipt — ${PRODUCT}`;
  const fragment = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  const tokenBytes = base64urlDecode(fragment);
  const valid =
    tokenBytes !== null &&
    tokenBytes.byteLength === 32 &&
    base64urlEncode(tokenBytes) === fragment;
  if (tokenBytes) {
    wipe(tokenBytes);
  }
  if (!valid) {
    main.replaceChildren(
      errorView(
        "This receipt link is incomplete.",
        "The receipt key must be the part after # in the sender's receipt link. Without it, this receipt cannot be shown.",
      ),
    );
    return;
  }

  const column = page();
  const stage = el("section", "stage");

  const statusTitle = el("h1", "display", "Loading receipt…");
  const statusSub = el("p", "stage-lede", "");

  const state = el("div", "state state--live");
  const stateLabel = el("span", "", "Connecting…");
  state.appendChild(stateLabel);

  const timeline = el("ol", "log");
  timeline.setAttribute("aria-live", "polite");

  const meta = el("div", "meta-list");
  const note = el(
    "p",
    "secret-note",
    "Keep this link private. It is the only credential that reads these events, and it stays after # so it is never sent.",
  );

  stage.append(state, statusTitle, statusSub, timeline);

  const rail = el("aside", "rail");
  rail.append(meta, note);

  const col = el("div", "col");
  col.appendChild(stage);
  const split = el("div", "split");
  split.append(col, rail);
  column.appendChild(split);
  main.replaceChildren(column);

  let stopped = false;
  let inFlight = false;
  let timer: number | undefined;
  // A burned receipt can still receive the recipient's "decrypted"
  // confirmation; poll a few times at a slower cadence, then stop for good.
  let afterBurnPolls = 0;
  let renderedEvents = "";
  const pollStartedAt = Date.now();
  const nextDelay = (): number => {
    const age = Date.now() - pollStartedAt;
    return age < 20_000 ? 2_000 : age < 120_000 ? 5_000 : age < 600_000 ? 15_000 : 60_000;
  };

  const schedule = (delay = POLL_MS): void => {
    if (stopped) {
      return;
    }
    timer = window.setTimeout(() => {
      void poll();
    }, delay);
  };

  const finish = (label: string): void => {
    stopped = true;
    stateLabel.textContent = label;
    state.className = "state state--done";
  };

  const poll = async (): Promise<void> => {
    if (stopped || inFlight) {
      return;
    }
    inFlight = true;
    try {
      const view = await fetchReceipt(id, fragment);
      renderView(view);
      if (view.decrypted || view.state === "expired" || view.state === "revoked") {
        finish("Final — no further events");
        return;
      }
      if (view.state === "burned") {
        afterBurnPolls += 1;
        if (afterBurnPolls > 3) {
          finish("Final — no further events");
          return;
        }
        stateLabel.textContent = "Burned — waiting for the final confirmation";
        schedule(10_000);
        return;
      }
      const delay = nextDelay();
      stateLabel.textContent = `Live — next check in ${delay / 1000} s`;
      schedule(delay);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        finish("Receipt closed");
        main.replaceChildren(
          errorView(
            "Receipt not found.",
            "The link is invalid or its retention window has ended. Ask the sender for a new secret if you need another receipt.",
          ),
        );
        return;
      }
      if (error instanceof ApiError && error.status === 429) {
        stateLabel.textContent = "Rate limited — retrying";
        schedule(5_000);
      } else {
        stateLabel.textContent = "Connection interrupted — retrying";
        schedule(3_000);
      }
    } finally {
      inFlight = false;
    }
  };

  const renderView = (view: ReceiptView): void => {
    const events = [...view.events].sort((a, b) => a.at - b.at);
    const has = (type: ReceiptEvent["type"]): boolean =>
      events.some((event) => event.type === type);
    const opened = view.opens > 0 || has("link_opened");
    const burned = has("burned");
    const decrypted = view.decrypted || has("decrypted");
    const expired = view.state === "expired" || has("expired");

    if (decrypted) {
      statusTitle.textContent = "Decrypted by the recipient.";
      statusSub.textContent =
        "The secret unlocked in their browser. The key was never received.";
    } else if (burned) {
      statusTitle.textContent = "Read and gone.";
      statusSub.textContent =
        "The secret was opened once and removed from memory.";
    } else if (expired) {
      statusTitle.textContent = "Expired unread.";
      statusSub.textContent = "The time limit passed before anyone revealed it.";
    } else if (view.state === "revoked") {
      statusTitle.textContent = "Revoked by the sender.";
      statusSub.textContent = "The record was destroyed before it was opened.";
    } else if (opened) {
      statusTitle.textContent = "Opened — waiting for confirmation.";
      statusSub.textContent = "The interstitial loaded. Nothing has been revealed yet.";
    } else {
      statusTitle.textContent = "Waiting for the first open.";
      statusSub.textContent = "No one has opened the link yet.";
    }

    // Rebuild only when the log actually changed: replacing identical rows
    // every two seconds makes an aria-live region re-read the whole list.
    const eventKey = events.map((event) => `${event.type}@${event.at}`).join("|");
    if (eventKey !== renderedEvents) {
      renderedEvents = eventKey;
      timeline.replaceChildren();
      for (const event of events) {
        timeline.appendChild(renderEvent(event));
      }
    }

    meta.replaceChildren();
    meta.append(
      metaRow("Receipt until", formatUTC(view.receiptExpiresAt)),
      metaRow("Secret expires", formatUTC(view.expiresAt)),
    );
    if (view.burnedAt) {
      meta.appendChild(metaRow("Burned at", formatUTC(view.burnedAt)));
    }
    if (view.revokedAt) {
      meta.appendChild(metaRow("Revoked at", formatUTC(view.revokedAt)));
    }
    if (view.opens > 0) {
      const last = view.lastOpenedAt
        ? ` · last ${formatUTC(view.lastOpenedAt)}`
        : "";
      meta.appendChild(metaRow("Link opens", `${view.opens}${last}`));
    }
    meta.appendChild(metaRow("Recorded", "Event type and UTC time only"));
  };

  const renderEvent = (event: ReceiptEvent): HTMLLIElement => {
    const copy = EVENT_COPY[event.type];
    const item = el("li", "log-row");
    item.append(
      el("span", "log-label", copy.label),
      el("time", "log-time", formatUTC(event.at)),
      el("p", "log-detail", copy.detail),
    );
    return item;
  };

  const onVisibility = (): void => {
    if (document.visibilityState === "hidden") {
      if (timer !== undefined) {
        window.clearTimeout(timer);
        timer = undefined;
      }
      stateLabel.textContent = "Paused while this tab is hidden";
    } else if (!stopped) {
      void poll();
    }
  };
  document.addEventListener("visibilitychange", onVisibility);
  window.addEventListener(
    "pagehide",
    () => {
      stopped = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    },
    { once: true },
  );

  void poll();
}

function metaRow(label: string, value: string): HTMLElement {
  const row = el("div", "meta-row");
  row.append(el("span", "", label), el("span", "mono", value));
  return row;
}

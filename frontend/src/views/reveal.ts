import { ApiError, confirmDecrypted, getChallenge, openSecret } from "../api.ts";
import {
  PBKDF2_ITERATIONS,
  cryptoUsable,
  decryptSecret,
  openProof,
  wipe,
} from "../crypto.ts";
import { el } from "../dom.ts";
import { formatRelative, formatUTC } from "../format.ts";
import { icon } from "../icons.ts";
import {
  readFragment,
  unlockFragment,
  type FragmentMaterial,
} from "../linkkey.ts";
import type { OpenResponse, PlaintextEnvelope } from "../types.ts";
import {
  formatWait,
  nextUnlockAttempts,
  readUnlockAttempts,
  writeUnlockAttempts,
} from "../unlocklimit.ts";
import { PRODUCT, copyButton, errorView, notice, page } from "./shared.ts";

export function renderReveal(main: HTMLElement, id: string): void {
  document.title = `A secret is waiting — ${PRODUCT}`;

  if (!cryptoUsable()) {
    main.replaceChildren(
      errorView(
        "This browser cannot decrypt secrets.",
        "Web Crypto with AES-256-GCM is required. Open the original link in a current browser over HTTPS.",
      ),
    );
    return;
  }

  const fragment = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  const material = readFragment(fragment);
  if (!material) {
    // After a reveal the fragment is stripped from the address bar, so a reload
    // lands here. Report that instead of claiming the sender's link is broken.
    main.replaceChildren(
      revealedHere(id)
        ? errorView(
            "This secret was already revealed.",
            "It was burned when you revealed it, and this tab cannot show it again. If you did not save it, ask the sender for a new secret.",
          )
        : incompleteLinkView(),
    );
    return;
  }

  let keyBytes: Uint8Array | null = material.version === 1 ? material.key : null;
  let challenge: string | null = null;
  let challengeExpiresAt = 0;
  let busy = false;
  let revealed: PlaintextEnvelope | null = null;
  let revealedOnce = false;
  let secretText = "";
  let burnedAt = 0;
  let countdown: number | undefined;
  let lockTimer: number | undefined;

  const stopCountdown = (): void => {
    if (countdown !== undefined) {
      window.clearInterval(countdown);
      countdown = undefined;
    }
  };

  const stopLock = (): void => {
    if (lockTimer !== undefined) {
      window.clearInterval(lockTimer);
      lockTimer = undefined;
    }
  };

  const cleanup = (): void => {
    stopCountdown();
    stopLock();
    if (keyBytes) {
      wipe(keyBytes);
      keyBytes = null;
    }
    revealed = null;
    secretText = "";
    const pre = document.getElementById("revealed-secret");
    if (pre) {
      pre.textContent = "";
    }
  };
  window.addEventListener("pagehide", cleanup);
  window.addEventListener("pageshow", (event) => {
    // A previous render's handler must not repaint the live view.
    if (!main.isConnected || !event.persisted) {
      return;
    }
    if (revealedOnce) {
      main.replaceChildren(
        errorView(
          "This secret was already revealed.",
          "It was burned when you revealed it, and this page cannot show it again. If you did not save it, ask the sender for a new secret.",
        ),
      );
      return;
    }
    // An app switch fires pagehide, which wipes the key from memory. The link
    // still holds it, so restore from the fragment instead of asking the
    // recipient to reload and start over.
    const replay = readFragment(
      location.hash.startsWith("#") ? location.hash.slice(1) : "",
    );
    if (replay?.version === 1) {
      keyBytes = replay.key;
      renderInterstitial();
      return;
    }
    if (replay?.version === 2) {
      renderPassphrase(replay);
      return;
    }
    if (keyBytes === null) {
      main.replaceChildren(
        errorView(
          "This page was left behind.",
          "The decryption key was cleared from memory. Reopen the complete original link to try again.",
          { label: "Reload", onClick: () => location.reload() },
        ),
      );
    }
  });

  const renderPassphrase = (
    wrapped: Extract<FragmentMaterial, { version: 2 }>,
  ): void => {
    document.title = `Passphrase required — ${PRODUCT}`;
    stopCountdown();

    const column = page();
    const stage = el("section", "stage");
    const form = el("form", "form");
    form.noValidate = true;

    const field = el("div", "field");
    const label = el("label", "field-label", "Passphrase");
    label.htmlFor = "passphrase-unlock";
    const input = el("input", "input input--mono");
    input.id = "passphrase-unlock";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("autocapitalize", "off");
    input.setAttribute("aria-describedby", "passphrase-unlock-hint");
    const hint = el(
      "p",
      "field-hint",
      "The sender set this separately from the link. Spaces and case matter. Wrong tries pause unlocking for a while.",
    );
    hint.id = "passphrase-unlock-hint";
    field.append(label, input, hint);

    const errorNode = el("p", "field-error");
    errorNode.hidden = true;
    errorNode.setAttribute("role", "alert");
    errorNode.tabIndex = -1;

    const actions = el("div", "actions");
    const submit = el("button", "btn btn-primary");
    submit.type = "submit";
    const submitIcon = el("span", "btn-icon");
    submitIcon.appendChild(icon("key", 15));
    const submitLabel = el("span", "", "Unlock link");
    submit.append(submitIcon, submitLabel);
    actions.appendChild(submit);

    form.append(field, errorNode, actions);

    stage.append(
      el("h1", "display", "This link is locked."),
      el(
        "p",
        "stage-lede",
        "Enter the passphrase the sender gave you. Nothing has been opened yet, and a wrong passphrase burns nothing.",
      ),
      form,
      el(
        "p",
        "secret-note",
        `The passphrase never leaves this browser. It unwraps the key in the link fragment with PBKDF2-SHA256, ${PBKDF2_ITERATIONS.toLocaleString("en-US")} rounds.`,
      ),
    );
    column.appendChild(stage);
    main.replaceChildren(column);

    const storageKey = `unkeep-unlock-${id}`;
    let attempts = readUnlockAttempts(storageKey);
    let unlocking = false;

    const showLock = (): void => {
      stopLock();
      const update = (): void => {
        const left = Math.ceil((attempts.lockedUntil - Date.now()) / 1000);
        if (left <= 0) {
          stopLock();
          errorNode.hidden = true;
          errorNode.textContent = "";
          submit.disabled = false;
          submitLabel.textContent = "Unlock link";
          return;
        }
        submit.disabled = true;
        submitLabel.textContent = left < 60 ? `Wait ${left}s` : `Wait ${Math.ceil(left / 60)}m`;
        errorNode.textContent = `Too many wrong passphrases. Try again in ${formatWait(left)}.`;
        errorNode.hidden = false;
      };
      update();
      if (Date.now() < attempts.lockedUntil) {
        lockTimer = window.setInterval(update, 500);
      }
    };

    if (Date.now() < attempts.lockedUntil) {
      showLock();
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (unlocking) {
        return;
      }
      if (Date.now() < attempts.lockedUntil) {
        showLock();
        errorNode.focus();
        return;
      }
      errorNode.hidden = true;
      errorNode.textContent = "";
      const passphrase = input.value;
      if (passphrase.length === 0) {
        errorNode.textContent = "Enter the passphrase.";
        errorNode.hidden = false;
        errorNode.focus();
        return;
      }
      unlocking = true;
      submit.disabled = true;
      submitLabel.textContent = "Unlocking…";
      try {
        keyBytes = await unlockFragment(wrapped, passphrase);
        attempts = { attempts: 0, lockedUntil: 0 };
        writeUnlockAttempts(storageKey, attempts);
        stopLock();
        input.value = "";
        // The unlock was the user's explicit action; go straight to the
        // confirmation step so a passphrase costs one fewer click.
        void loadChallenge(null);
      } catch {
        attempts = nextUnlockAttempts(attempts, Date.now());
        writeUnlockAttempts(storageKey, attempts);
        if (attempts.lockedUntil > Date.now()) {
          showLock();
        } else {
          errorNode.textContent =
            "That passphrase did not unlock this link. Nothing was burned.";
          errorNode.hidden = false;
        }
        errorNode.focus();
      } finally {
        unlocking = false;
        if (keyBytes === null && Date.now() >= attempts.lockedUntil) {
          submit.disabled = false;
          submitLabel.textContent = "Unlock link";
        }
      }
    });
  };

  const renderInterstitial = (): void => {
    document.title = `A secret is waiting — ${PRODUCT}`;
    stopCountdown();
    const column = page();
    const stage = el("section", "stage");

    const row = el("div", "actions");
    const openButton = el("button", "btn btn-primary", "Open secret");
    openButton.type = "button";
    openButton.addEventListener("click", () => {
      void loadChallenge(openButton);
    });
    row.appendChild(openButton);

    stage.append(
      el("h1", "display", "Someone sent you a secret."),
      el(
        "p",
        "stage-lede",
        "It can be read once. Opening this page changes nothing; the message is destroyed only when you reveal it.",
      ),
      row,
      el(
        "p",
        "secret-note",
        "Link previews and automated fetchers cannot burn it.",
      ),
    );
    withRail(column, stage, "The sender will see when you open it.", "Only the event and its time. No IP address, device, or location is recorded.");
    main.replaceChildren(column);
  };

  const loadChallenge = async (
    trigger: HTMLButtonElement | null,
  ): Promise<void> => {
    if (busy) {
      return;
    }
    stopCountdown();
    busy = true;
    if (trigger) {
      trigger.disabled = true;
      trigger.textContent = "Checking…";
    }
    try {
      const response = await getChallenge(id);
      challenge = response.challenge;
      challengeExpiresAt = response.challengeExpiresAt;
      renderConfirmation(response.expiresAt, response.challengeExpiresAt);
    } catch (error) {
      if (error instanceof ApiError && error.status === 410) {
        renderUnavailable();
      } else if (error instanceof ApiError && error.status === 429) {
        renderRateLimited();
      } else {
        main.replaceChildren(
          errorView(
            "Could not reach the service.",
            "Check your connection and try again. Nothing was revealed.",
            { label: "Try again", onClick: () => location.reload() },
          ),
        );
      }
    } finally {
      busy = false;
    }
  };

  const renderConfirmation = (
    expiresAt: number,
    confirmUntil: number,
  ): void => {
    document.title = `Read it once — ${PRODUCT}`;
    const column = page();
    const stage = el("section", "stage");

    const facts = el("dl", "facts");
    const relative = el("dd", "", formatRelative(expiresAt));
    const confirmLeft = el("dd", "", formatRelative(confirmUntil));
    facts.append(
      factItemNode("Expires", el("dd", "mono", formatUTC(expiresAt))),
      factItemNode("Time left", relative),
      factItemNode("Confirm within", confirmLeft),
      factItemNode("Reads left", el("dd", "", "1")),
    );

    const row = el("div", "actions");
    const revealButton = el("button", "btn btn-primary");
    revealButton.type = "button";
    const revealIcon = el("span", "btn-icon");
    revealIcon.appendChild(icon("eye", 16));
    const revealLabel = el("span", "", "Reveal secret");
    revealButton.append(revealIcon, revealLabel);
    const notYet = el("button", "btn btn-quiet", "Not yet");
    notYet.type = "button";
    notYet.addEventListener("click", renderInterstitial);
    revealButton.addEventListener("click", () => {
      void revealSecret(revealButton, notYet);
    });
    row.append(revealButton, notYet);

    const steps = el("ol", "steps");
    [
      "The stored copy is deleted before your browser decrypts it.",
      "The key is removed from the address bar.",
      "This page shows the secret once. Nothing can reopen it.",
    ].forEach((text, index) => {
      const item = el("li");
      item.append(el("span", "n", String(index + 1)), el("span", "", text));
      steps.appendChild(item);
    });
    const lede = el("p", "stage-lede");
    lede.append(
      document.createTextNode("Make sure you are ready to save it."),
      document.createElement("br"),
      document.createTextNode("Closing the tab afterwards does not bring it back."),
    );

    stage.append(
      el("h1", "display", "Read it once."),
      lede,
      facts,
      row,
      steps,
    );
    withRail(column, stage, "After this, it is gone.", "Saving it is on you. It cannot be sent again.");
    main.replaceChildren(column);

    const update = (): void => {
      relative.textContent = formatRelative(expiresAt);
      const left = confirmUntil - Date.now();
      confirmLeft.textContent = left > 0 ? formatRelative(confirmUntil) : "expired";
      if (left <= 0) {
        stopCountdown();
        revealButton.disabled = true;
        revealLabel.textContent = "Confirmation expired";
        notYet.textContent = "Start over";
      }
    };
    update();
    countdown = window.setInterval(update, 1000);
  };

  const revealSecret = async (
    revealButton: HTMLButtonElement,
    notYet: HTMLButtonElement,
  ): Promise<void> => {
    if (
      busy ||
      !challenge ||
      !keyBytes ||
      (challengeExpiresAt > 0 && Date.now() >= challengeExpiresAt)
    ) {
      return;
    }
    stopCountdown();
    busy = true;
    revealButton.disabled = true;
    notYet.disabled = true;
    const label = revealButton.querySelector("span:last-child");
    if (label) {
      label.textContent = "Revealing…";
    }

    // Once the server has released the ciphertext the record is gone. Until
    // then a 429, an expired challenge, or a dropped connection leaves the
    // secret intact, so the key and the URL fragment must survive: wiping them
    // would destroy a link the sender can still see as unread.
    const discardMaterial = (): void => {
      if (keyBytes) {
        wipe(keyBytes);
        keyBytes = null;
      }
      history.replaceState(null, "", location.pathname);
    };

    const retry = (): void => {
      void loadChallenge(null);
    };

    try {
      const proof = await openProof(keyBytes);
      let opened: OpenResponse;
      try {
        opened = await openSecret(id, challenge, proof);
      } catch (error) {
        if (error instanceof ApiError) {
          if (error.status === 429) {
            main.replaceChildren(
              errorView(
                "Too many attempts.",
                "Wait a minute, then try again. Nothing was revealed and nothing was burned.",
                { label: "Try again", onClick: retry },
              ),
            );
            return;
          }
          if (error.status === 403 && isChallengeExpiry(error)) {
            main.replaceChildren(
              errorView(
                "The confirmation window closed.",
                "Nothing was revealed and nothing was burned. Confirm again to continue.",
                { label: "Try again", onClick: retry },
              ),
            );
            return;
          }
        }
        if (isTransportFailure(error)) {
          main.replaceChildren(
            errorView(
              "No answer from the server.",
              "The request did not complete. If it was already released, this link will show as opened; otherwise nothing was burned.",
              { label: "Try again", onClick: retry },
            ),
          );
          return;
        }
        discardMaterial();
        if (error instanceof ApiError && error.status === 410) {
          renderUnavailable();
        } else {
          renderCouldNotOpen();
        }
        return;
      }

      const plaintext = await decryptSecret(opened.envelope, keyBytes);
      burnedAt = opened.burnedAt;
      discardMaterial();
      const confirmation = confirmDecrypted(id, opened.viewToken).catch(
        () => undefined,
      );
      revealed = plaintext;
      secretText = plaintext.secret;
      renderSecret();
      await confirmation;
    } catch {
      // openProof or decryptSecret failed: the ciphertext is already burned or
      // never left the browser.
      discardMaterial();
      renderCouldNotOpen();
    } finally {
      busy = false;
    }
  };

  const renderSecret = (): void => {
    document.title = `Secret revealed — ${PRODUCT}`;
    stopCountdown();
    revealedOnce = true;
    markRevealed(id);
    const column = page();
    const stage = el("section", "stage");

    const panel = el("section", "secret");
    const status = el("div", "secret-status");
    status.append(
      el("span", "mark", "Read and gone."),
      el("span", "", "This is the only copy."),
      el("time", "", formatUTC(burnedAt)),
    );

    const pre = el("pre", "secret-text");
    pre.id = "revealed-secret";
    pre.textContent = secretText;

    const actions = el("div", "secret-actions");
    actions.append(
      copyButton(() => secretText, "Copy secret", "btn btn-primary"),
      (() => {
        const clearButton = el("button", "btn btn-quiet", "Clear from screen");
        clearButton.type = "button";
        clearButton.addEventListener("click", clearFromScreen);
        return clearButton;
      })(),
    );

    panel.append(status, pre, actions);
    stage.append(
      el("h1", "display", "Here it is."),
      el(
        "p",
        "stage-lede",
        "This is no longer stored. Save it now if you need it.",
      ),
      panel,
      el(
        "p",
        "secret-note",
        "The key was removed from the address bar.",
      ),
    );
    column.appendChild(stage);
    main.replaceChildren(column);
  };

  const clearFromScreen = (): void => {
    document.title = `Cleared — ${PRODUCT}`;
    stopCountdown();
    revealedOnce = true;
    secretText = "";
    revealed = null;
    const pre = document.getElementById("revealed-secret");
    if (pre) {
      pre.textContent = "";
    }

    const column = page();
    const stage = el("section", "stage");
    const actions = el("div", "actions");
    const home = el("a", "btn btn-quiet", "Create a secret");
    home.href = "/";
    actions.appendChild(home);
    stage.append(
      el("h1", "display", "Cleared."),
      el(
        "p",
        "stage-lede",
        "The text is gone from this page and no copy is kept. If you did not save it, it cannot be recovered.",
      ),
      notice(
        "info",
        "Browser memory cannot be zeroed. ",
        "The reference is gone, but the string may linger in memory until the tab closes.",
      ),
      actions,
    );
    column.appendChild(stage);
    main.replaceChildren(column);
  };

  const renderUnavailable = (): void => {
    document.title = `Secret unavailable — ${PRODUCT}`;
    stopCountdown();
    main.replaceChildren(
      errorView(
        "This secret is no longer available.",
        "It may have been revealed already, expired, or destroyed by the sender. A one-view secret cannot be opened twice.",
      ),
    );
  };

  const renderRateLimited = (): void => {
    stopCountdown();
    main.replaceChildren(
      errorView(
        "Too many attempts.",
        "Wait a minute, then reload the complete original link.",
        { label: "Reload", onClick: () => location.reload() },
      ),
    );
  };

  const renderCouldNotOpen = (): void => {
    stopCountdown();
    main.replaceChildren(
      errorView(
        "This secret could not be opened.",
        "The key in this link does not match the stored copy, or the stored copy was already released. Nothing else changes: if it was released, it cannot be opened again.",
      ),
    );
  };

  if (material.version === 2) {
    renderPassphrase(material);
  } else {
    renderInterstitial();
  }
}

const REVEALED_PREFIX = "unkeep-revealed-";

function revealedHere(id: string): boolean {
  try {
    return sessionStorage.getItem(REVEALED_PREFIX + id) === "1";
  } catch {
    return false;
  }
}

function markRevealed(id: string): void {
  try {
    sessionStorage.setItem(REVEALED_PREFIX + id, "1");
  } catch {
    // Storage may be unavailable; the in-memory flag still covers this page.
  }
}

function isChallengeExpiry(error: ApiError): boolean {
  return error.message.toLowerCase().includes("expired");
}

function isTransportFailure(error: unknown): boolean {
  return (
    error instanceof TypeError ||
    (error instanceof DOMException &&
      (error.name === "AbortError" || error.name === "TimeoutError"))
  );
}

function factItemNode(label: string, value: HTMLElement): HTMLElement {
  const item = el("div", "fact");
  item.append(el("dt", "", label), value);
  return item;
}

function incompleteLinkView(): HTMLElement {
  return errorView(
    "This link is incomplete.",
    "The decryption key is missing. It is the part after # in the sender's link; ask for the complete URL.",
  );
}

function withRail(
  column: HTMLElement,
  stage: HTMLElement,
  statement: string,
  detail: string,
): void {
  const col = el("div", "col");
  col.appendChild(stage);
  const rail = el("aside", "rail");
  rail.append(el("p", "statement", statement), el("p", "", detail));
  const split = el("div", "split");
  split.append(col, rail);
  column.appendChild(split);
}

import { ApiError, createSecret } from "../api.ts";
import {
  MAX_SECRET_BYTES,
  cryptoUsable,
  decryptSecret,
  encryptSecret,
  generateKeyMaterial,
  openProof,
  wipe,
} from "../crypto.ts";
import { el } from "../dom.ts";
import { formatBytes } from "../format.ts";
import { icon } from "../icons.ts";
import { encodeFragment } from "../linkkey.ts";
import { generatePassphrase } from "../passphrase.ts";
import type { SecretEnvelope } from "../types.ts";
import { PRODUCT_TITLE, copyButton, notice, page, pageHead } from "./shared.ts";
import { renderResult } from "./result.ts";

const EXPIRY_OPTIONS = [
  { seconds: 300, label: "5 min" },
  { seconds: 3_600, label: "1 hour" },
  { seconds: 86_400, label: "24 hours" },
  { seconds: 604_800, label: "7 days" },
] as const;

const encoder = new TextEncoder();

export function renderCreate(main: HTMLElement): void {
  document.title = PRODUCT_TITLE;
  const canEncrypt = cryptoUsable();

  const column = page();
  const head = pageHead(
    "Say it once. Then it's gone.",
    "The secret is encrypted in your browser, so the copy stored here is never readable. You get a link that opens one time.",
  );

  const form = el("form", "form");
  form.noValidate = true;

  const secretField = el("div", "field");
  const secretHead = el("div", "field-head");
  const textarea = el("textarea", "textarea");
  textarea.id = "secret-input";
  textarea.name = "secret";
  textarea.rows = 5;
  textarea.placeholder = "Paste a password, key, or code…";
  textarea.autocomplete = "off";
  textarea.spellcheck = false;
  textarea.setAttribute("autocapitalize", "off");
  textarea.setAttribute("aria-describedby", "secret-counter");

  const counterRow = el("div", "field-meta");
  const counter = el("span", "counter-value", `0 B / ${formatBytes(MAX_SECRET_BYTES)}`);
  counter.id = "secret-counter";
  counterRow.append(
    counter,
  );
  secretHead.append(counterRow);
  secretField.append(secretHead, textarea);

  const expirySet = el("fieldset", "choice");
  const legend = el("legend", "field-label", "Delete if unread after");
  const options = el("div", "choice-options");
  for (const option of EXPIRY_OPTIONS) {
    const wrapper = el("label", "choice-option");
    const radio = el("input");
    radio.type = "radio";
    radio.name = "expiry";
    radio.value = String(option.seconds);
    radio.checked = option.seconds === 3_600;
    wrapper.append(radio, el("span", "", option.label));
    options.appendChild(wrapper);
  }
  expirySet.append(legend, options);

  const passphraseSet = el("div", "field");
  const passphraseRow = el("label", "switch-row");
  const passphraseCopy = el("span", "switch-copy");
  const passphraseTitle = el("span", "field-label", "Add a passphrase");
  passphraseTitle.id = "passphrase-title";
  passphraseCopy.append(passphraseTitle);

  const passphraseToggle = el("input");
  passphraseToggle.type = "checkbox";
  passphraseToggle.id = "use-passphrase";
  passphraseToggle.setAttribute("role", "switch");
  passphraseToggle.setAttribute("aria-labelledby", "passphrase-title");
  const passphraseSwitch = el("span", "switch");
  const passphraseTrack = el("span", "switch-track");
  passphraseTrack.setAttribute("aria-hidden", "true");
  passphraseSwitch.append(passphraseToggle, passphraseTrack);
  passphraseRow.append(passphraseCopy, passphraseSwitch);

  const passphraseBox = el("div", "passphrase-box");
  passphraseBox.hidden = true;
  const passphraseLabel = el("label", "field-label", "Passphrase");
  passphraseLabel.htmlFor = "passphrase-input";
  const passphraseInput = el("input", "input input--mono");
  passphraseInput.id = "passphrase-input";
  passphraseInput.autocomplete = "off";
  passphraseInput.spellcheck = false;
  passphraseInput.setAttribute("autocapitalize", "off");
  passphraseInput.setAttribute("aria-describedby", "passphrase-hint");
  const passphraseHint = el(
    "p",
    "field-hint",
    "At least 8 characters. Share it another way. Without it, the link is useless.",
  );
  passphraseHint.id = "passphrase-hint";
  const passphraseControl = el("div", "passphrase-control");
  const generate = el("button", "phrase-generate", "Generate");
  generate.type = "button";
  generate.title = "Generate a memorable passphrase";
  generate.setAttribute("aria-label", "Generate a passphrase");
  generate.addEventListener("click", () => {
    const phrase = generatePassphrase();
    passphraseInput.value = phrase;
    passphraseInput.focus();
    passphraseInput.setSelectionRange(phrase.length, phrase.length);
    // Say the trade-off where it is made: five random words are easy to retype
    // and only about 25 bits, so an offline guess is slowed, not prevented.
    passphraseHint.textContent =
      "Generated phrases are easy to retype but only ~25 bits: a speed bump, not a secret. For anything valuable, type your own long passphrase. Share it another way; without it the link is useless.";
  });
  const copyPhrase = copyButton(() => passphraseInput.value, "Copy", "phrase-copy");
  copyPhrase.title = "Copy passphrase";
  copyPhrase.setAttribute("aria-label", "Copy passphrase");
  const phraseActions = el("div", "phrase-actions");
  phraseActions.append(copyPhrase, generate);
  passphraseControl.append(passphraseInput, phraseActions);
  passphraseBox.append(passphraseLabel, passphraseControl, passphraseHint);
  passphraseSet.append(passphraseRow, passphraseBox);

  passphraseToggle.addEventListener("change", () => {
    passphraseBox.hidden = !passphraseToggle.checked;
    if (passphraseToggle.checked) {
      passphraseInput.focus();
    } else {
      passphraseInput.value = "";
    }
    updateLinkNotice();
  });

  const warn = el("div", "callout");
  const warnDot = el("span", "callout-dot");
  warnDot.setAttribute("aria-hidden", "true");
  const warnCopy = el("p", "callout-copy");
  warn.append(warnDot, warnCopy);
  const updateLinkNotice = (): void => {
    warnCopy.replaceChildren();
    if (passphraseToggle.checked) {
      warnCopy.append(
        el("strong", "", "Whoever has both the link and the passphrase gets the secret."),
        el("br"),
        document.createTextNode(
          " Share them another way, and don't post either where others can see it. It cannot be recovered.",
        ),
      );
      return;
    }
    warnCopy.append(
      el("strong", "", "Whoever opens the link first gets the secret."),
      el("br"),
      document.createTextNode(
        " Don't send it somewhere that saves history, or post it where others can see it. It cannot be recovered.",
      ),
    );
  };
  updateLinkNotice();

  const errorNode = el("p", "form-error");
  errorNode.hidden = true;
  errorNode.setAttribute("role", "alert");
  errorNode.tabIndex = -1;

  const actions = el("div", "actions");
  const submit = el("button", "btn btn-primary btn-wide");
  submit.type = "submit";
  const submitIcon = el("span", "btn-icon");
  submitIcon.appendChild(icon("lock", 16));
  const submitLabel = el("span", "", "Create one-time link");
  submit.append(submitIcon, submitLabel);
  actions.appendChild(submit);
  if (!canEncrypt) {
    actions.prepend(
      notice(
        "danger",
        "This browser cannot encrypt.",
        "Web Crypto with AES-256-GCM is required. Open this page over HTTPS in a current browser; the button stays disabled until then.",
      ),
    );
  }

  form.append(secretField, expirySet, passphraseSet, warn, errorNode, actions);

  const rail = el("aside", "rail");
  const flow = el("ol", "flow");
  for (const step of ["Write it", "Lock it", "Send the link"]) {
    const item = el("li");
    const dot = el("span", "flow-dot");
    dot.setAttribute("aria-hidden", "true");
    item.append(dot, el("span", "", step));
    flow.appendChild(item);
  }
  rail.append(
    flow,
    (() => {
      const note = el("p", "rail-note");
      note.append(
        document.createTextNode("Once it's opened, it's deleted."),
        document.createElement("br"),
        document.createTextNode("Nothing is kept."),
      );
      return note;
    })(),
  );
  const col = el("div", "col");
  col.append(head, form);
  const split = el("div", "split");
  split.append(col, rail);
  column.appendChild(split);
  main.appendChild(column);

  let busy = false;
  const fitTextarea = (): void => {
    textarea.style.height = "auto";
    textarea.style.height = `${Math.min(textarea.scrollHeight + 2, 384)}px`;
  };
  const refreshCounter = (): void => {
    const bytes = encoder.encode(textarea.value).byteLength;
    counter.textContent = `${formatBytes(bytes)} / ${formatBytes(MAX_SECRET_BYTES)}`;
    const over = bytes > MAX_SECRET_BYTES;
    counter.classList.toggle("counter--over", over);
    textarea.setAttribute("aria-invalid", over ? "true" : "false");
    submit.disabled = !canEncrypt || busy || over;
  };
  const showError = (message: string): void => {
    errorNode.textContent = message;
    errorNode.hidden = false;
    errorNode.focus();
  };
  const hideError = (): void => {
    errorNode.hidden = true;
    errorNode.textContent = "";
  };
  const setBusy = (next: boolean): void => {
    busy = next;
    submitLabel.textContent = next ? "Locking…" : "Create one-time link";
    form.setAttribute("aria-busy", next ? "true" : "false");
    refreshCounter();
  };

  textarea.addEventListener("input", () => {
    fitTextarea();
    refreshCounter();
  });
  textarea.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      form.requestSubmit();
    }
  });
  window.addEventListener(
    "pagehide",
    () => {
      textarea.value = "";
      passphraseInput.value = "";
    },
    { once: true },
  );
  fitTextarea();
  refreshCounter();

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !canEncrypt) {
      return;
    }
    hideError();

    let secret = textarea.value;
    if (secret.length === 0) {
      showError("Paste a secret first.");
      textarea.focus();
      return;
    }
    if (encoder.encode(secret).byteLength > MAX_SECRET_BYTES) {
      showError("That's too large. Keep it under 16 KB.");
      textarea.focus();
      return;
    }

    const selected = form.querySelector<HTMLInputElement>(
      'input[name="expiry"]:checked',
    );
    const ttlSeconds = selected ? Number(selected.value) : 3_600;
    if (!EXPIRY_OPTIONS.some((option) => option.seconds === ttlSeconds)) {
      showError("Choose an expiry.");
      return;
    }

    const usePassphrase = passphraseToggle.checked;
    const passphrase = usePassphrase ? passphraseInput.value : "";
    if (usePassphrase && passphrase.length < 8) {
      showError("Use at least 8 characters, or turn the passphrase off.");
      passphraseInput.focus();
      return;
    }

    const keyBytes = generateKeyMaterial();
    const createdAt = Date.now();
    const expiresAt = createdAt + ttlSeconds * 1_000;
    setBusy(true);
    try {
      const parts = await encryptSecret(secret, keyBytes, {
        createdAt,
        expiresAt,
        maxViews: 1,
      });
      const envelope: SecretEnvelope = {
        v: 1,
        alg: "A256GCM",
        iv: parts.iv,
        ciphertext: parts.ciphertext,
        tag: parts.tag,
        createdAt,
        expiresAt,
        maxViews: 1,
      };
      // A one-view secret is unrecoverable after the server burns it. Prove the
      // envelope decrypts locally before uploading, so a browser or code fault
      // cannot create a link that fails after the only copy is gone.
      const verification = await decryptSecret(envelope, keyBytes);
      if (verification.secret !== secret) {
        throw new Error("verification failed");
      }
      const proof = await openProof(keyBytes);
      // PBKDF2 (600k rounds) only wraps the fragment the sender will copy; the
      // upload does not depend on it, so both run at once.
      const [keyMaterial, result] = await Promise.all([
        encodeFragment(keyBytes, passphrase),
        createSecret(envelope, ttlSeconds, proof),
      ]);
      const shareUrl = `${location.origin}/s/${encodeURIComponent(result.secretId)}#${keyMaterial}`;
      const receiptUrl = `${location.origin}/receipt/${encodeURIComponent(result.secretId)}#${result.receiptToken}`;

      textarea.value = "";
      passphraseInput.value = "";
      secret = "";
      wipe(keyBytes);
      renderResult(main, {
        secretId: result.secretId,
        receiptToken: result.receiptToken,
        shareUrl,
        receiptUrl,
        expiresAt: result.expiresAt,
        receiptExpiresAt: result.receiptExpiresAt,
        passphraseUsed: usePassphrase,
      });
    } catch (error) {
      wipe(keyBytes);
      showError(describeError(error));
    } finally {
      setBusy(false);
    }
  });
}




function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 429) {
      return "Too many attempts. Wait a minute and try again.";
    }
    if (error.status === 503) {
      return "The service is temporarily full. Try again shortly.";
    }
    return error.message;
  }
  if (error instanceof TypeError) {
    return "Could not reach the service. Check your connection and try again.";
  }
  if (error instanceof Error && error.message === "verification failed") {
    return "This browser could not verify the encrypted link. Nothing was sent. Try again or use a different browser.";
  }
  return "This browser could not encrypt the secret. Try a current browser.";
}

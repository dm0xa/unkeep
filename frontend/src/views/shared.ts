import { append, el } from "../dom.ts";
import { brandOpenU, githubMark, icon, type IconName } from "../icons.ts";

export const PRODUCT = "unkeep";
export const PRODUCT_TITLE = "unkeep — one-time secret link";

export function renderShell(root: HTMLElement): HTMLElement {
  const skip = el("a", "skip-link", "Skip to content");
  skip.href = "#main";

  const masthead = el("header", "masthead");
  const brand = el("a", "masthead-brand");
  brand.href = "/";
  brand.setAttribute("aria-label", `${PRODUCT} home`);
  append(brand, brandOpenU(22), el("span", "brand-word", "nkeep"));
  const tools = el("div", "masthead-tools");
  const help = helpControl();
  tools.append(help.button, themeToggle());
  masthead.append(brand, tools);

  const main = el("main", "main");
  main.id = "main";
  main.tabIndex = -1;

  const foot = el("footer", "foot");
  const footInner = el("div", "foot-inner");
  const repo = el("a", "foot-link foot-link--icon");
  repo.href = "https://github.com/dm0xa/unkeep";
  repo.target = "_blank";
  repo.rel = "noreferrer noopener";
  repo.setAttribute("aria-label", "Source code on GitHub");
  repo.title = "Source code on GitHub";
  repo.appendChild(githubMark(16));
  footInner.append(
    el("span", "", "No accounts, no database, no plaintext."),
    repo,
  );
  foot.appendChild(footInner);

  const app = el("div", "app");
  app.append(skip, masthead, main, foot, help.dialog);
  root.replaceChildren(app);
  return main;
}

function helpControl(): { button: HTMLButtonElement; dialog: HTMLDialogElement } {
  const button = el("button", "help-toggle", "?");
  button.type = "button";
  button.setAttribute("aria-label", "How unkeep works");
  button.title = "How unkeep works";

  const dialog = el("dialog", "help-dialog");
  dialog.id = "how-it-works";
  dialog.setAttribute("aria-labelledby", "help-title");
  dialog.setAttribute("aria-describedby", "help-lede");
  button.setAttribute("aria-haspopup", "dialog");
  button.setAttribute("aria-controls", dialog.id);

  const head = el("div", "help-head");
  const title = el("h2", "help-title", "How it works");
  title.id = "help-title";
  const close = el("button", "help-close", "Close");
  close.type = "button";
  head.append(title, close);

  const lede = el(
    "p",
    "help-lede",
    "Your browser encrypts the secret before it leaves the page. The key lives only after # in the link, so the server never receives it.",
  );
  lede.id = "help-lede";

  const steps = el("ol", "help-steps");
  steps.append(
    (() => {
      const item = el("li");
      item.append(el("strong", "", "Encrypt locally."), " A fresh AES-256-GCM key is generated in your browser.");
      return item;
    })(),
    (() => {
      const item = el("li");
      item.append(el("strong", "", "Store ciphertext."), " The server keeps only encrypted bytes in volatile memory.");
      return item;
    })(),
    (() => {
      const item = el("li");
      item.append(el("strong", "", "Open once."), " The first reveal deletes the server copy; it cannot be fetched again.");
      return item;
    })(),
  );

  const note = el(
    "p",
    "help-note",
    "Receipts record only the event and its UTC time. No IP address, device, or location is collected.",
  );

  dialog.append(head, lede, steps, note);
  button.addEventListener("click", () => {
    if (!dialog.open) {
      dialog.showModal();
    }
  });
  close.addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) {
      dialog.close();
    }
  });

  return { button, dialog };
}

/** A page column, the only layout primitive this surface has. */
export function page(wide = false): HTMLElement {
  return el("div", wide ? "page page--wide" : "page");
}

/** Title and one line of context. No kicker, no rule. */
export function pageHead(title: string, lede?: string): HTMLElement {
  const head = el("header", "page-head");
  head.appendChild(el("h1", "display", title));
  if (lede) {
    head.appendChild(el("p", "lede", lede));
  }
  return head;
}

/** A label/value row for metadata lists. */
export function recordRow(label: string, value: string, mono = false): HTMLElement {
  const row = el("dl", "meta-row");
  row.append(el("dt", "", label), el("dd", mono ? "mono" : "", value));
  return row;
}

export type NoticeKind = "warn" | "danger" | "info" | "success";

/**
 * A quiet inline note. No box, no icon tray: a sentence with a lead-in.
 */
export function notice(
  kind: NoticeKind,
  title: string,
  body: string,
  iconName: IconName = "shield",
): HTMLElement {
  void iconName;
  const node = el("p", kind === "danger" || kind === "warn" ? "note note--danger" : "note");
  const lead = el("strong", "", title);
  node.append(lead, document.createTextNode(body));
  return node;
}

export function copyButton(
  getText: () => string,
  label = "Copy",
  variant = "btn",
): HTMLButtonElement {
  const button = el("button", variant);
  button.type = "button";
  const iconSlot = el("span");
  iconSlot.appendChild(icon("copy", 15));
  const labelNode = el("span", "", label);
  const dot = el("span", "btn-dot");
  dot.setAttribute("aria-hidden", "true");
  button.append(iconSlot, labelNode, dot);

  let timer: number | undefined;
  button.addEventListener("click", async () => {
    const text = getText();
    if (!text) {
      return;
    }
    let copied = false;
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
    } catch {
      copied = fallbackCopy(text);
    }
    if (timer !== undefined) {
      window.clearTimeout(timer);
    }
    labelNode.textContent = copied ? "Copied" : "Select manually";
    button.dataset["state"] = copied ? "done" : "failed";
    timer = window.setTimeout(() => {
      labelNode.textContent = label;
      delete button.dataset["state"];
    }, 1800);
  });
  return button;
}

function fallbackCopy(text: string): boolean {
  const area = el("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.inset = "0 auto auto 0";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  area.remove();
  return ok;
}

export function loadingView(title: string, detail: string): HTMLElement {
  const column = page();
  const stage = el("section", "stage");
  stage.append(el("h1", "display", title), el("p", "stage-lede", detail), el("p", "loading", "Working…"));
  column.appendChild(stage);
  return column;
}

export function errorView(
  title: string,
  message: string,
  action?: { label: string; onClick: () => void },
): HTMLElement {
  const column = page();
  const stage = el("section", "stage");
  stage.append(el("h1", "display", title), el("p", "stage-lede", message));
  const actions = el("div", "actions");
  if (action) {
    const button = el("button", "btn btn-primary", action.label);
    button.type = "button";
    button.addEventListener("click", action.onClick);
    actions.appendChild(button);
  }
  const home = el("a", "btn btn-quiet", "Create a secret");
  home.href = "/";
  actions.appendChild(home);
  stage.appendChild(actions);
  column.appendChild(stage);
  return column;
}

type ThemeChoice = "light" | "dark";

const THEME_KEY = "unkeep-theme";

function systemPrefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function resolvedTheme(): ThemeChoice {
  const chosen = document.documentElement.dataset["theme"];
  if (chosen === "light" || chosen === "dark") {
    return chosen;
  }
  return systemPrefersDark() ? "dark" : "light";
}

function paintThemeMeta(theme: ThemeChoice): void {
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    meta.setAttribute("content", theme === "dark" ? "#0b0c0e" : "#ffffff");
  }
}

function applyTheme(theme: ThemeChoice): void {
  document.documentElement.dataset["theme"] = theme;
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    // Private mode or blocked storage: the choice holds for this view only.
  }
  paintThemeMeta(theme);
}

/** One control: moon when the page is light, sun when it is dark. */
function themeToggle(): HTMLElement {
  const button = el("button", "theme-toggle");
  button.type = "button";

  const render = (): void => {
    const theme = resolvedTheme();
    const next = theme === "dark" ? "Light" : "Dark";
    button.replaceChildren(icon(theme === "dark" ? "sun" : "moon", 18));
    button.setAttribute("aria-label", `Switch to ${next.toLowerCase()} theme`);
    button.title = `Switch to ${next.toLowerCase()} theme`;
  };

  button.addEventListener("click", () => {
    applyTheme(resolvedTheme() === "dark" ? "light" : "dark");
    render();
  });

  // With no stored choice the page follows the OS, so the glyph must too.
  window
    .matchMedia("(prefers-color-scheme: dark)")
    .addEventListener("change", () => {
      if (!document.documentElement.dataset["theme"]) {
        render();
      }
    });

  render();
  return button;
}

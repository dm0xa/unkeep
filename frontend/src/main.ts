import { errorView, renderShell } from "./views/shared.ts";
import { renderCreate } from "./views/create.ts";
import { renderReveal } from "./views/reveal.ts";
import { renderReceipt } from "./views/receipt.ts";

const root = document.getElementById("app");

if (root) {
  render();
  window.addEventListener("popstate", render);
  // Same-origin links to SPA routes navigate in place: a full reload would
  // re-download and re-parse the bundle to show the same document.
  document.addEventListener("click", (event) => {
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    ) {
      return;
    }
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }
    const anchor = target.closest("a");
    if (
      !(anchor instanceof HTMLAnchorElement) ||
      anchor.target ||
      anchor.hasAttribute("download") ||
      anchor.origin !== location.origin ||
      anchor.search
    ) {
      return;
    }
    const path = anchor.pathname.replace(/\/+$/, "") || "/";
    if (!isAppRoute(path)) {
      return;
    }
    event.preventDefault();
    history.pushState(null, "", path);
    window.scrollTo(0, 0);
    render();
  });
}

function isAppRoute(path: string): boolean {
  return path === "/" || /^\/(s|receipt)\/[^/]+$/.test(path);
}

function render(): void {
  if (!root) {
    return;
  }
  root.replaceChildren();
  const main = renderShell(root);
  const path = location.pathname.replace(/\/+$/, "") || "/";

  if (path === "/") {
    renderCreate(main);
    return;
  }

  const secret = path.match(/^\/s\/([^/]+)$/);
  if (secret?.[1]) {
    const id = safeDecode(secret[1]);
    if (id) {
      renderReveal(main, id);
      return;
    }
  }

  const receipt = path.match(/^\/receipt\/([^/]+)$/);
  if (receipt?.[1]) {
    const id = safeDecode(receipt[1]);
    if (id) {
      renderReceipt(main, id);
      return;
    }
  }

  document.title = "Page not found — unkeep";
  main.appendChild(
    errorView(
      "Page not found.",
      "That route does not exist. If you followed a secret link, make sure you copied the complete URL including the part after #.",
    ),
  );
}

function safeDecode(value: string): string | null {
  try {
    const decoded = decodeURIComponent(value);
    return decoded.length > 0 && !decoded.includes("/") ? decoded : null;
  } catch {
    return null;
  }
}

import { errorView, renderShell } from "./views/shared.ts";
import { renderCreate } from "./views/create.ts";
import { renderReveal } from "./views/reveal.ts";
import { renderReceipt } from "./views/receipt.ts";

const root = document.getElementById("app");

if (root) {
  render();
  window.addEventListener("popstate", render);
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

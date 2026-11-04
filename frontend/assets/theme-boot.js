/* Sets the stored theme before first paint, so a manual choice never flashes
   the other scheme. Kept as a plain file outside the bundle: it has to run
   ahead of the app, and CSP forbids an inline script. */
(function () {
  var root = document.documentElement;
  var stored = null;
  try {
    stored = window.localStorage.getItem("unkeep-theme");
  } catch (error) {
    stored = null;
  }

  if (stored === "light" || stored === "dark") {
    root.setAttribute("data-theme", stored);
  }

  var dark =
    stored === "dark" ||
    (stored !== "light" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches);

  var meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    meta.setAttribute("content", dark ? "#0b0c0e" : "#ffffff");
  }
})();

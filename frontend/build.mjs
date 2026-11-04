import { cp, mkdir, rm } from "node:fs/promises";
import { build } from "esbuild";

await rm("dist", { recursive: true, force: true });
await mkdir("dist", { recursive: true });

await build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["es2022"],
  outfile: "dist/app.js",
  minify: true,
  sourcemap: false,
  legalComments: "none",
  charset: "utf8",
});

await cp("index.html", "dist/index.html");
await cp("styles.css", "dist/styles.css");
await cp("favicon.svg", "dist/favicon.svg");
await cp("assets", "dist/assets", { recursive: true });

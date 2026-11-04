import { stat } from "node:fs/promises";

const budgets = [
  ["dist/app.js", 44 * 1024],
  ["dist/styles.css", 30 * 1024],
  ["dist/index.html", 8 * 1024],
];

let failed = false;
for (const [file, budget] of budgets) {
  const { size } = await stat(file);
  const status = size <= budget ? "ok" : "over";
  console.log(`${status.padEnd(3)} ${file.padEnd(18)} ${size} B / ${budget} B`);
  if (size > budget) {
    failed = true;
  }
}
if (failed) {
  process.exitCode = 1;
}

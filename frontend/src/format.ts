const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

export function formatUTC(ms: number): string {
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) {
    return "Unknown time";
  }
  const iso = date.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 23)} UTC`;
}

export function formatRelative(ms: number, now = Date.now()): string {
  const delta = ms - now;
  const abs = Math.abs(delta);
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["day", 86_400_000],
    ["hour", 3_600_000],
    ["minute", 60_000],
    ["second", 1_000],
  ];
  for (const [unit, size] of units) {
    if (abs >= size || unit === "second") {
      return relative.format(Math.round(delta / size), unit);
    }
  }
  return relative.format(0, "second");
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  return `${(bytes / 1024).toFixed(1)} KB`;
}

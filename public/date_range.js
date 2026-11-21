export function midnight(date, days = 0) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate() + days);
}

export function dayString(date) {
  return [String(date.getFullYear()).padStart(4, "0"), String(date.getMonth() + 1).padStart(2, "0"), String(date.getDate()).padStart(2, "0")].join("-");
}

export function readDate(text) {
  const [year, month, day] = text.split("-").map(Number);
  return new Date(year, month - 1, day);
}

export function presetRange(preset) {
  const end = midnight(new Date(), preset === "yesterday" ? -1 : 0);
  return {start: midnight(end, 1 - (Number(preset) || 1)), end};
}

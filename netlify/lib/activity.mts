// Works out, in plain words, what one save changed, for the Activity list. Kept separate so it can be tested.
type Doc = Record<string, unknown> | null;
type Todo = { id?: string; text?: string; done?: boolean; dueAt?: number };
export type Entry = { t: number; who: string; k: string; ev: string; title: string; what: string[]; owner?: string };

const q = (t: unknown) => "“" + String(t ?? "").slice(0, 40) + "”";
const todos = (d: Doc): Todo[] => (Array.isArray(d?.todo) ? (d!.todo as Todo[]) : []);
const differ = (a: Doc, b: Doc, keys: string[]) => keys.some((k) => JSON.stringify(a?.[k] ?? "") !== JSON.stringify(b?.[k] ?? ""));

export function listChanges(prev: Doc, next: Doc): string[] {
  const out: string[] = [];
  const before = new Map(todos(prev).map((t) => [String(t.id), t]));
  const after = new Map(todos(next).map((t) => [String(t.id), t]));
  for (const [id, t] of after) {
    const o = before.get(id);
    if (!o) out.push("added " + q(t.text) + " to the list");
    else if (!o.done && t.done) out.push("ticked off " + q(t.text));
    else if (o.done && !t.done) out.push("unticked " + q(t.text));
    else if ((o.dueAt || 0) !== (t.dueAt || 0)) out.push((t.dueAt ? "set a reminder for " : "removed the reminder for ") + q(t.text));
  }
  for (const [id, t] of before) if (!after.has(id)) out.push("removed " + q(t.text) + " from the list");
  return out;
}

/** What changed between the stored event and the one being saved. Empty when nothing worth mentioning did. */
export function describe(prev: Doc, next: Doc): string[] {
  if (!prev) return ["added this event"];
  const out: string[] = [];
  if (differ(prev, next, ["title"])) out.push("renamed it");
  if (differ(prev, next, ["y", "m", "d", "mode"])) out.push("changed the date");
  if (differ(prev, next, ["time"])) out.push(next?.time ? "changed the time" : "removed the time");
  if (differ(prev, next, ["loc", "addr"])) out.push(next?.loc ? "changed the place" : "removed the place");
  if (differ(prev, next, ["note"])) out.push("updated the note");
  out.push(...listChanges(prev, next));
  if (differ(prev, next, ["priv"])) out.push(next?.priv ? "made it private" : "shared it");
  if (differ(prev, next, ["icon", "color", "scene", "transport", "flags", "important", "repeat"])) out.push("changed how it looks");
  return out;
}

/** Adds an entry to the newest-first list; quick successive changes to one event by one phone become one entry. */
export function addEntry(list: Entry[], e: Entry, max = 60): Entry[] {
  const top = list[0];
  if (top && top.ev === e.ev && top.k === e.k && (top.owner || "") === (e.owner || "") && e.t - top.t < 10 * 60 * 1000 && e.what[0] !== "removed this event") {
    const what = top.what[0] === "added this event" ? top.what : [...new Set([...e.what, ...top.what])].slice(0, 5);
    return [{ ...top, t: e.t, title: e.title, what }, ...list.slice(1)];
  }
  return [e, ...list].slice(0, max);
}

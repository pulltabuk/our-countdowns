// Works out which reminders on one stored event are due. Kept separate from the scheduled function so it can be tested.
export type Todo = { id?: string; text?: string; done?: boolean; dueAt?: number };
export type Due = { todoId: string; text: string; dueAt: number };

const WINDOW = 36 * 60 * 60 * 1000; // a reminder missed by more than a day and a half is dropped, not sent late

export function dueReminders(doc: { todo?: unknown } | null, now: number): Due[] {
  const list = Array.isArray(doc?.todo) ? (doc!.todo as Todo[]) : [];
  return list
    .filter((t) => t && !t.done && typeof t.dueAt === "number" && t.dueAt > 0 && t.dueAt <= now && t.dueAt > now - WINDOW && t.id && t.text)
    .map((t) => ({ todoId: String(t.id), text: String(t.text), dueAt: t.dueAt as number }));
}

/** "bh-christmas-day" -> "Christmas Day": automatic dates are stored by slug, without their title. */
export function titleFromSlug(slug: string): string {
  return slug
    .replace(/^(bh|x)-/, "")
    .split("-")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

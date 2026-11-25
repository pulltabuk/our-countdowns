import { getStore } from "@netlify/blobs";
import type { Config } from "@netlify/functions";
import webpush from "web-push";
import { dueReminders, titleFromSlug } from "../lib/due.mts";

// Runs every five minutes. Sends a phone notification for each "thing to remember" whose reminder time has arrived.
export default async () => {
  const s = getStore({ name: "countdowns", consistency: "strong" });
  const keys = (await s.get("vapid", { type: "json" })) as { publicKey: string; privateKey: string } | null;
  if (!keys) return; // nobody has turned notifications on yet

  const now = Date.now();
  const subject = Netlify.env.get("URL") || "https://our-countdowns-k7q4.netlify.app";
  const subs = (await s.list({ prefix: "push/" })).blobs.map((b) => b.key);
  if (!subs.length) return;

  const send = async (subKey: string, title: string, body: string) => {
    const sub = (await s.get(subKey, { type: "json" })) as webpush.PushSubscription | null;
    if (!sub) return;
    try {
      await webpush.sendNotification(sub, JSON.stringify({ title, body }), {
        TTL: 86400,
        vapidDetails: { subject, publicKey: keys.publicKey, privateKey: keys.privateKey },
      });
    } catch (e) {
      const code = (e as { statusCode?: number }).statusCode;
      if (code === 404 || code === 410) await s.delete(subKey);
      else console.error("reminder push failed", code);
    }
  };

  const docs = [
    ...(await s.list({ prefix: "ev/" })).blobs.map((b) => ({ key: b.key, auto: false })),
    ...(await s.list({ prefix: "ao/" })).blobs.map((b) => ({ key: b.key, auto: true })),
  ];
  for (const d of docs) {
    const doc = (await s.get(d.key, { type: "json" })) as { title?: string; owner?: string; todo?: unknown } | null;
    const due = dueReminders(doc, now);
    if (!due.length) continue;
    const id = d.key.slice(3);
    const title = d.auto ? titleFromSlug(id) : String(doc?.title || "Our Countdowns");
    // a private event's reminders go only to the phone that owns it
    const targets = doc?.owner ? subs.filter((k) => k === "push/" + doc.owner) : subs;
    for (const r of due) {
      // one marker per reminder time, so each is sent once even though this runs repeatedly
      const { modified } = await s.set(`rem/${id}/${r.todoId}/${r.dueAt}`, "1", { onlyIfNew: true });
      if (!modified) continue;
      await Promise.allSettled(targets.map((k) => send(k, "Reminder: " + title, r.text)));
    }
  }
};

export const config: Config = { schedule: "*/5 * * * *" };

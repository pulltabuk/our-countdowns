import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

// One blob per date (no read-modify-write), plus one config blob holding the passcode hash.
const store = () => getStore({ name: "countdowns", consistency: "strong" });

// The dates that existed before the move; written once, when the passcode is first created.
const SEED: Record<string, unknown>[] = [
  { id: "8j5m22irac6zh1nuapya", title: "Brussels", mode: "day", y: 2026, m: 12, d: 10, icon: "✈️", color: "jade", repeat: false, note: "", createdAt: 1795218910747 },
  { id: "ex-christmas", title: "Christmas Eve", mode: "day", y: 2026, m: 12, d: 24, icon: "🎄", color: "jade", repeat: true, note: "", createdAt: 1795190000000 },
  { id: "ex-ski", title: "Ski trip", mode: "day", y: 2027, m: 2, d: 28, icon: "🎿", color: "cobalt", repeat: false, note: "", example: true, createdAt: 1795190000000 },
  { id: "ex-summer", title: "Summer holiday", mode: "month", y: 2027, m: 7, d: 1, icon: "🏝️", color: "rose", repeat: false, note: "Dates not fixed yet", example: true, createdAt: 1795190000000 },
  { id: "ex-weekend", title: "Weekend away", mode: "day", y: 2026, m: 11, d: 30, icon: "🧳", color: "marigold", repeat: false, note: "", example: true, createdAt: 1795190000000 },
];

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

const hash = (pass: string, salt: string) => scryptSync(pass, salt, 32).toString("hex");
const str = (v: unknown, max: number) => String(v ?? "").slice(0, max);
const int = (v: unknown, lo: number, hi: number, dflt: number) => {
  const n = Math.round(Number(v));
  return Number.isFinite(n) && n >= lo && n <= hi ? n : dflt;
};

function clean(b: Record<string, unknown>) {
  const title = str(b.title, 60).trim();
  if (!title) return null;
  const out: Record<string, unknown> = {
    title,
    mode: b.mode === "month" ? "month" : "day",
    y: int(b.y, 1900, 2200, 0),
    m: int(b.m, 1, 12, 1),
    d: int(b.d, 1, 31, 1),
    icon: str(b.icon, 16),
    color: str(b.color, 16),
    scene: str(b.scene, 16),
    repeat: !!b.repeat,
    important: !!b.important,
    note: str(b.note, 200),
    createdAt: int(b.createdAt, 0, 9e15, Date.now()),
  };
  if (!out.y) return null;
  if (b.example) out.example = true;
  return out;
}

export default async (req: Request, context: Context) => {
  const s = store();
  const parts = new URL(req.url).pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const [head, id] = parts;
  const cfg = (await s.get("config", { type: "json" })) as { salt: string; hash: string } | null;

  if (head === "status" && req.method === "GET") return json({ claimed: !!cfg });

  if (head === "claim" && req.method === "POST") {
    const body = (await req.json().catch(() => ({}))) as { pass?: unknown };
    const pass = str(body.pass, 100);
    if (pass.length < 6) return json({ error: "short" }, 400);
    const salt = randomBytes(16).toString("hex");
    const { modified } = await s.setJSON("config", { salt, hash: hash(pass, salt) }, { onlyIfNew: true });
    if (!modified) return json({ error: "claimed" }, 409);
    for (const ev of SEED) {
      const { id: seedId, ...rest } = ev;
      await s.setJSON("ev/" + seedId, rest, { onlyIfNew: true });
    }
    return json({ ok: true });
  }

  // Everything below needs the shared passcode.
  if (!cfg) return json({ error: "unclaimed" }, 401);
  const given = Buffer.from(hash(req.headers.get("x-pass") || "", cfg.salt), "hex");
  const want = Buffer.from(cfg.hash, "hex");
  if (given.length !== want.length || !timingSafeEqual(given, want)) return json({ error: "auth" }, 401);

  if (head !== "events") return json({ error: "not found" }, 404);

  if (!id && req.method === "GET") {
    const { blobs } = await s.list({ prefix: "ev/" });
    const events = (
      await Promise.all(
        blobs.map(async (b) => {
          const data = (await s.get(b.key, { type: "json" })) as Record<string, unknown> | null;
          return data ? { ...data, id: b.key.slice(3) } : null;
        }),
      )
    ).filter(Boolean);
    return json({ events });
  }

  if (!id || !/^[A-Za-z0-9_-]{1,40}$/.test(id)) return json({ error: "bad id" }, 400);

  if (req.method === "PUT") {
    const data = clean((await req.json().catch(() => ({}))) as Record<string, unknown>);
    if (!data) return json({ error: "invalid" }, 400);
    await s.setJSON("ev/" + id, data);
    return json({ ok: true });
  }
  if (req.method === "DELETE") {
    await s.delete("ev/" + id);
    return json({ ok: true });
  }
  return json({ error: "method" }, 405);
};

export const config: Config = {
  path: ["/api", "/api/*"],
  // Slows down passcode guessing; normal use is one sync every 20 seconds.
  rateLimit: { windowLimit: 40, windowSize: 60, aggregateBy: ["ip", "domain"] },
};

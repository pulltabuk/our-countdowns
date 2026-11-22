import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

// One blob per date (no read-modify-write), plus one config blob holding the passcode hash.
const store = () => getStore({ name: "countdowns", consistency: "strong" });

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
    transport: str(b.transport, 12),
    by: /^[A-Za-z0-9_-]{1,40}$/.test(String(b.by ?? "")) ? String(b.by) : "",
    todo: (Array.isArray(b.todo) ? b.todo : []).slice(0, 40).map((t: Record<string, unknown>) => ({
      id: str(t?.id, 20),
      text: str(t?.text, 80).trim(),
      done: !!t?.done,
      by: str(t?.by, 40),
    })).filter((t) => t.id && t.text),
    repeat: !!b.repeat,
    important: !!b.important,
    priv: !!b.priv,
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
  const cfg = (await s.get("config", { type: "json" })) as { salt: string; hash: string; adminHash?: string } | null;

  if (head === "status" && req.method === "GET") return json({ claimed: !!cfg, hasAdmin: !!cfg?.adminHash });

  if (head === "claim" && req.method === "POST") {
    const body = (await req.json().catch(() => ({}))) as { pass?: unknown };
    const pass = str(body.pass, 100);
    if (pass.length < 6) return json({ error: "short" }, 400);
    const salt = randomBytes(16).toString("hex");
    const { modified } = await s.setJSON("config", { salt, hash: hash(pass, salt) }, { onlyIfNew: true });
    if (!modified) return json({ error: "claimed" }, 409);
    return json({ ok: true });
  }

  // Everything below needs the shared passcode.
  if (!cfg) return json({ error: "unclaimed" }, 401);
  const given = Buffer.from(hash(req.headers.get("x-pass") || "", cfg.salt), "hex");
  const want = Buffer.from(cfg.hash, "hex");
  if (given.length !== want.length || !timingSafeEqual(given, want)) return json({ error: "auth" }, 401);

  // The administrator is one phone holding a secret key; only it may change the shared passcode.
  const sha = (v: string) => createHash("sha256").update(v).digest("hex");
  const adminKey = req.headers.get("x-admin") || "";
  // "Only me" events belong to one phone: each phone sends its own secret key, and a private
  // event is stored with that key's hash and only ever returned to the phone that holds it.
  const deviceKey = req.headers.get("x-key") || "";
  const keyHash = deviceKey.length >= 32 ? sha(deviceKey) : "";
  const isAdmin = !!cfg.adminHash && adminKey.length >= 32 && sha(adminKey) === cfg.adminHash;

  if (head === "admin" && req.method === "POST") {
    if (cfg.adminHash) return json({ error: "taken" }, 409);
    const b = (await req.json().catch(() => ({}))) as { key?: unknown };
    const key = str(b.key, 200);
    if (key.length < 32) return json({ error: "invalid" }, 400);
    await s.setJSON("config", { ...cfg, adminHash: sha(key) });
    await s.set("meta/rev", String(Date.now()));
    return json({ ok: true });
  }

  if (head === "passcode" && req.method === "POST") {
    if (!isAdmin) return json({ error: "admin" }, 403);
    const b = (await req.json().catch(() => ({}))) as { pass?: unknown };
    const next = str(b.pass, 100);
    if (next.length < 6) return json({ error: "short" }, 400);
    const salt = randomBytes(16).toString("hex");
    await s.setJSON("config", { ...cfg, salt, hash: hash(next, salt) });
    return json({ ok: true });
  }

  // "rev" changes on every write, so phones can poll it cheaply and only reload when it moves.
  const bump = () => s.set("meta/rev", String(Date.now()));
  if (head === "rev" && req.method === "GET") return json({ rev: (await s.get("meta/rev")) || "0" });

  if (head === "profiles" && req.method === "PUT") {
    if (!id || !/^[A-Za-z0-9_-]{1,40}$/.test(id)) return json({ error: "bad id" }, 400);
    const b = (await req.json().catch(() => ({}))) as Record<string, unknown>;
    const name = str(b.name, 24).trim();
    const photo = String(b.photo ?? "");
    if (!name) return json({ error: "invalid" }, 400);
    if (photo && (!photo.startsWith("data:image/jpeg;base64,") || photo.length > 80000)) return json({ error: "photo" }, 400);
    await s.setJSON("pf/" + id, { name, photo });
    await bump();
    return json({ ok: true });
  }

  if (head !== "events") return json({ error: "not found" }, 404);

  if (!id && req.method === "GET") {
    const { blobs } = await s.list({ prefix: "ev/" });
    const events = (
      await Promise.all(
        blobs.map(async (b) => {
          const data = (await s.get(b.key, { type: "json" })) as Record<string, unknown> | null;
          if (!data) return null;
          const { owner, ...rest } = data;
          if (owner && owner !== keyHash) return null;
          return { ...rest, id: b.key.slice(3) };
        }),
      )
    ).filter(Boolean);
    const pf = await s.list({ prefix: "pf/" });
    const profiles = (
      await Promise.all(
        pf.blobs.map(async (b) => {
          const data = (await s.get(b.key, { type: "json" })) as Record<string, unknown> | null;
          return data ? { ...data, id: b.key.slice(3) } : null;
        }),
      )
    ).filter(Boolean);
    return json({ rev: (await s.get("meta/rev")) || "0", events, profiles, hasAdmin: !!cfg.adminHash, admin: isAdmin });
  }

  if (!id || !/^[A-Za-z0-9_-]{1,40}$/.test(id)) return json({ error: "bad id" }, 400);

  const prev = (await s.get("ev/" + id, { type: "json" })) as { owner?: string } | null;
  if (prev?.owner && prev.owner !== keyHash) return json({ error: "private" }, 403);

  if (req.method === "PUT") {
    const data = clean((await req.json().catch(() => ({}))) as Record<string, unknown>);
    if (!data) return json({ error: "invalid" }, 400);
    if (data.priv) {
      if (!keyHash) return json({ error: "key" }, 400);
      data.owner = keyHash;
    }
    await s.setJSON("ev/" + id, data);
    await bump();
    return json({ ok: true });
  }
  if (req.method === "DELETE") {
    await s.delete("ev/" + id);
    await bump();
    return json({ ok: true });
  }
  return json({ error: "method" }, 405);
};

export const config: Config = {
  path: ["/api", "/api/*"],
  // Slows down passcode guessing; normal use is one small check every 6 seconds per phone.
  rateLimit: { windowLimit: 90, windowSize: 60, aggregateBy: ["ip", "domain"] },
};

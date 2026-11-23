import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import webpush from "web-push";
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
    time: /^([01]\d|2[0-3]):[0-5]\d$/.test(String(b.time ?? "")) ? String(b.time) : "",
    loc: str(b.loc, 80).trim(),
    addr: str(b.addr, 200).trim(),
    lat: typeof b.lat === "number" && Math.abs(b.lat) <= 90 ? b.lat : null,
    lon: typeof b.lon === "number" && Math.abs(b.lon) <= 180 ? b.lon : null,
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

  // Suggestions while typing a place, from Photon (an OpenStreetMap search built for search-as-you-type).
  if (head === "suggest" && req.method === "GET") {
    const q = str(new URL(req.url).searchParams.get("q"), 80).trim();
    if (q.length < 3) return json({ places: [] });
    try {
      const r = await fetch("https://photon.komoot.io/api/?limit=6&lang=en&lat=52.8&lon=-1.6&q=" + encodeURIComponent(q), {
        headers: { "User-Agent": "OurCountdowns/1.0 (private two-person countdown app)" },
        signal: AbortSignal.timeout(6000),
      });
      const data = (await r.json()) as { features?: { properties?: Record<string, unknown>; geometry?: { coordinates?: number[] } }[] };
      const seen = new Set<string>();
      const places = (data.features || [])
        .map((f) => {
          const p = f.properties || {};
          const c = f.geometry?.coordinates || [];
          const road = [p.housenumber, p.street].filter(Boolean).join(" ");
          const name = str(p.name || road || p.city, 80);
          const parts = [road, p.district, p.city, p.county, p.postcode, p.country].map((x) => str(x, 60)).filter((x) => x && x !== name);
          const addr = [...new Set(parts)].join(", ");
          return { name, addr, lat: Number(c[1]), lon: Number(c[0]) };
        })
        .filter((x) => x.name && Number.isFinite(x.lat) && Number.isFinite(x.lon) && !seen.has(x.name + x.addr) && seen.add(x.name + x.addr));
      return json({ places });
    } catch {
      return json({ places: [] });
    }
  }

  // Turn a typed place into map coordinates using OpenStreetMap's search, remembering each answer.
  if (head === "geo" && req.method === "GET") {
    const q = str(new URL(req.url).searchParams.get("q"), 80).trim();
    if (q.length < 2) return json({ found: false });
    const key = "geo/" + sha(q.toLowerCase());
    const hit = (await s.get(key, { type: "json" })) as { lat: number; lon: number; addr?: string } | null;
    if (hit) return json({ found: true, ...hit });
    try {
      const r = await fetch("https://nominatim.openstreetmap.org/search?format=jsonv2&limit=1&accept-language=en&q=" + encodeURIComponent(q), {
        headers: { "User-Agent": "OurCountdowns/1.0 (private two-person countdown app)", Referer: new URL(req.url).origin + "/" },
        signal: AbortSignal.timeout(8000),
      });
      const list = (await r.json()) as { lat?: string; lon?: string; display_name?: string }[];
      const lat = Number(list?.[0]?.lat);
      const lon = Number(list?.[0]?.lon);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) return json({ found: false });
      const addr = str(list?.[0]?.display_name, 200);
      await s.setJSON(key, { lat, lon, addr });
      return json({ found: true, lat, lon, addr });
    } catch {
      return json({ found: false });
    }
  }

  // UK bank holidays come from the government's published list, cached here for a week at a time.
  if (head === "holidays" && req.method === "GET") {
    const cached = (await s.get("bankhols", { type: "json" })) as { at: number; events: { title: string; date: string }[] } | null;
    if (cached && Date.now() - cached.at < 7 * 864e5 && cached.events.length) return json({ events: cached.events });
    try {
      const r = await fetch("https://www.gov.uk/bank-holidays.json", { signal: AbortSignal.timeout(8000) });
      const all = (await r.json()) as Record<string, { events?: { title?: unknown; date?: unknown }[] }>;
      const events = (all["england-and-wales"]?.events || [])
        .map((e) => ({ title: str(e.title, 60), date: str(e.date, 10) }))
        .filter((e) => e.title && /^\d{4}-\d{2}-\d{2}$/.test(e.date));
      if (!events.length) throw new Error("empty");
      await s.setJSON("bankhols", { at: Date.now(), events });
      return json({ events });
    } catch {
      return json({ events: cached?.events || [] });
    }
  }

  // Automatic dates (bank holidays and the like) cannot be renamed or moved, but their look and list can be changed.
  if (head === "auto" && req.method === "PUT") {
    if (!id || !/^[a-z0-9-]{1,60}$/.test(id)) return json({ error: "bad id" }, 400);
    const b = (await req.json().catch(() => ({}))) as Record<string, unknown>;
    const full = clean({ ...b, title: "x", y: 2000, m: 1, d: 1 });
    if (!full) return json({ error: "invalid" }, 400);
    await s.setJSON("ao/" + id, { color: full.color, icon: full.icon, scene: full.scene, important: full.important, todo: full.todo });
    await bump();
    return json({ ok: true });
  }

  // Push notifications: each phone that opts in stores its subscription under its own key.
  const vapid = async () => {
    let v = (await s.get("vapid", { type: "json" })) as { publicKey: string; privateKey: string } | null;
    if (!v) {
      await s.setJSON("vapid", webpush.generateVAPIDKeys(), { onlyIfNew: true });
      v = (await s.get("vapid", { type: "json" })) as { publicKey: string; privateKey: string };
    }
    return v;
  };
  if (head === "push") {
    if (req.method === "GET") return json({ key: (await vapid()).publicKey });
    if (!keyHash) return json({ error: "key" }, 400);
    if (req.method === "DELETE") {
      await s.delete("push/" + keyHash);
      return json({ ok: true });
    }
    if (req.method === "POST") {
      const b = (await req.json().catch(() => ({}))) as { sub?: { endpoint?: unknown; keys?: { p256dh?: unknown; auth?: unknown } } };
      const endpoint = str(b.sub?.endpoint, 1000);
      const p256dh = str(b.sub?.keys?.p256dh, 200);
      const auth = str(b.sub?.keys?.auth, 100);
      if (!/^https:\/\//.test(endpoint) || !p256dh || !auth) return json({ error: "invalid" }, 400);
      await s.setJSON("push/" + keyHash, { endpoint, keys: { p256dh, auth } });
      return json({ ok: true });
    }
    return json({ error: "method" }, 405);
  }
  const notifyOthers = async (title: string, by: string) => {
    const keys = await vapid();
    const who = by ? ((await s.get("pf/" + by, { type: "json" })) as { name?: string } | null)?.name : "";
    const payload = JSON.stringify({ title: "New countdown", body: (who ? who + " added " : "Added: ") + title });
    const { blobs } = await s.list({ prefix: "push/" });
    await Promise.allSettled(
      blobs.filter((b) => b.key !== "push/" + keyHash).map(async (b) => {
        const sub = (await s.get(b.key, { type: "json" })) as webpush.PushSubscription | null;
        if (!sub) return;
        try {
          await webpush.sendNotification(sub, payload, {
            TTL: 86400,
            vapidDetails: { subject: new URL(req.url).origin, publicKey: keys.publicKey, privateKey: keys.privateKey },
          });
        } catch (e) {
          const code = (e as { statusCode?: number }).statusCode;
          if (code === 404 || code === 410) await s.delete(b.key);
          else console.error("push failed", code);
        }
      }),
    );
  };

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
    const ao = await s.list({ prefix: "ao/" });
    const auto: Record<string, unknown> = {};
    await Promise.all(
      ao.blobs.map(async (b) => {
        const data = await s.get(b.key, { type: "json" });
        if (data) auto[b.key.slice(3)] = data;
      }),
    );
    return json({ rev: (await s.get("meta/rev")) || "0", events, profiles, auto, hasAdmin: !!cfg.adminHash, admin: isAdmin });
  }

  if (!id || !/^[A-Za-z0-9_-]{1,40}$/.test(id)) return json({ error: "bad id" }, 400);

  const prev = (await s.get("ev/" + id, { type: "json" })) as { owner?: string } | null;
  if (prev?.owner && prev.owner !== keyHash) return json({ error: "private" }, 403);

  if (req.method === "PUT") {
    const data = clean((await req.json().catch(() => ({}))) as Record<string, unknown>);
    if (!data) return json({ error: "invalid" }, 400);
    data.updatedAt = Date.now();
    if (data.priv) {
      if (!keyHash) return json({ error: "key" }, 400);
      data.owner = keyHash;
    }
    await s.setJSON("ev/" + id, data);
    await bump();
    // Tell the other phone about a brand-new shared event; never about private ones or edits.
    if (!prev && !data.priv) context.waitUntil(notifyOthers(String(data.title), String(data.by || "")).catch((e) => console.error("notify", e)));
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

import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import webpush from "web-push";
import { KEEP, addEntry, describe, listChanges, type Entry } from "../lib/activity.mts";
import { titleFromSlug } from "../lib/due.mts";
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
    flags: (Array.isArray(b.flags) ? b.flags : []).map((f: unknown) => String(f)).filter((f: string) => /^[A-Z]{2}(-[A-Z]{3})?$/.test(f)).slice(0, 3),
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
      due: /^\d{4}-\d{2}-\d{2}$/.test(String(t?.due ?? "")) ? String(t.due) : "",
      dueTime: /^([01]\d|2[0-3]):[0-5]\d$/.test(String(t?.dueTime ?? "")) ? String(t.dueTime) : "",
      dueAt: typeof t?.dueAt === "number" && t.dueAt > 0 && t.dueAt < 9e15 ? t.dueAt : 0,
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
  let cfg = (await s.get("config", { type: "json" })) as { salt: string; hash: string; adminHash?: string; adminReset?: string } | null;

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
  // One-off: the administrator's phone was replaced without its key being carried across, which left the role
  // held by nobody. Hand it back so it can be claimed again (once only; the marker stops this repeating).
  if (cfg.adminHash && cfg.adminReset !== "r1") {
    cfg = { salt: cfg.salt, hash: cfg.hash, adminReset: "r1" };
    await s.setJSON("config", cfg);
    await s.set("meta/rev", String(Date.now()));
  } else if (!cfg.adminReset) {
    cfg = { ...cfg, adminReset: "r1" };
    await s.setJSON("config", cfg);
  }
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

  // Moving to a new phone or a fresh copy of the app: the old copy parks its keys under a short code
  // for half an hour, and the new copy (which must also know the passcode) collects them once.
  if (head === "move") {
    if (req.method === "POST") {
      if (!keyHash) return json({ error: "key" }, 400);
      const b = (await req.json().catch(() => ({}))) as { me?: unknown };
      const code = String(100000 + (randomBytes(4).readUInt32BE(0) % 900000));
      await s.setJSON("mv/" + code, { key: deviceKey, admin: isAdmin ? adminKey : "", me: str(b.me, 40), exp: Date.now() + 30 * 60 * 1000 });
      return json({ code });
    }
    if (req.method === "GET" && /^\d{6}$/.test(id || "")) {
      const m = (await s.get("mv/" + id, { type: "json" })) as { key: string; admin: string; me: string; exp: number } | null;
      if (m) await s.delete("mv/" + id);
      if (!m || m.exp < Date.now()) return json({ error: "code" }, 404);
      // anything this copy picked up under its own temporary key (a claimed name, new private events) follows it to the moved key
      const moved = sha(m.key);
      if (keyHash && keyHash !== moved) {
        for (const prefix of ["pf/", "ev/"]) {
          for (const b of (await s.list({ prefix })).blobs) {
            const doc = (await s.get(b.key, { type: "json" })) as Record<string, unknown> | null;
            if (doc && prefix === "pf/" && doc.k === keyHash) await s.setJSON(b.key, { ...doc, k: moved });
            if (doc && prefix === "ev/" && doc.owner === keyHash) await s.setJSON(b.key, { ...doc, owner: moved });
          }
        }
        await s.set("meta/rev", String(Date.now()));
      }
      return json({ key: m.key, admin: m.admin, me: m.me });
    }
    return json({ error: "method" }, 405);
  }

  // A private event is locked to the phone that made it. If that copy of the app is gone and its key was not
  // moved, the event is stranded. The administrator can bring such events to their phone by naming one of them:
  // every private event locked to the same lost phone comes back. Phones still in use are never touched.
  if (head === "recover" && req.method === "POST") {
    if (!isAdmin) return json({ error: "admin" }, 403);
    if (!keyHash) return json({ error: "key" }, 400);
    const norm = (v: unknown) => String(v ?? "").toLowerCase().replace(/\s+/g, " ").trim();
    const want = norm(str(((await req.json().catch(() => ({}))) as { title?: unknown }).title, 60));
    if (want.length < 3) return json({ error: "short" }, 400);
    const inUse = new Set<string>();
    for (const b of (await s.list({ prefix: "pf/" })).blobs) {
      const p = (await s.get(b.key, { type: "json" })) as { k?: string } | null;
      if (p?.k) inUse.add(p.k);
    }
    const since = Date.now() - 60 * 864e5;
    for (const b of (await s.list({ prefix: "seen/" })).blobs) if (Number(await s.get(b.key)) > since) inUse.add(b.key.slice(5));
    const docs = await Promise.all(
      (await s.list({ prefix: "ev/" })).blobs.map(async (b) => ({ key: b.key, doc: (await s.get(b.key, { type: "json" })) as Record<string, unknown> | null })),
    );
    const lost = new Set<string>();
    for (const { doc } of docs) {
      const owner = String(doc?.owner || "");
      if (!owner || owner === keyHash || inUse.has(owner)) continue;
      const t = norm(doc?.title);
      if (t === want || (want.length >= 5 && t.includes(want))) lost.add(owner);
    }
    let recovered = 0;
    for (const { key, doc } of docs) {
      if (!doc || !lost.has(String(doc.owner || ""))) continue;
      await s.setJSON(key, { ...doc, owner: keyHash });
      recovered++;
    }
    if (recovered) await s.set("meta/rev", String(Date.now()));
    return json({ recovered });
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
  // Activity: a short running list of who added or changed what, shown on the Activity screen.
  // Each name belongs to one phone: a profile stores the hash of that phone's key ("k"), and a phone is only
  // believed about who it is when the name it gives is its own (or not yet claimed by any phone).
  type Pf = { name: string; photo: string; k?: string };
  const meRaw = req.headers.get("x-me") || "";
  const meId = /^[A-Za-z0-9_-]{1,40}$/.test(meRaw) ? meRaw : "";
  let whoKnown: string | undefined;
  const whoIs = async () => {
    if (whoKnown !== undefined) return whoKnown;
    whoKnown = "";
    if (meId) {
      const p = (await s.get("pf/" + meId, { type: "json" })) as Pf | null;
      if (p && (!p.k || p.k === keyHash)) whoKnown = meId;
    }
    return whoKnown;
  };
  const log = async (ev: string, title: string, what: string[], owner?: string) => {
    if (!what.length) return;
    try {
      const list = ((await s.get("act", { type: "json" })) as Entry[] | null) || [];
      await s.setJSON("act", addEntry(list, { t: Date.now(), who: await whoIs(), k: keyHash, ev, title, what, ...(owner ? { owner } : {}) }));
    } catch (e) {
      console.error("activity", e);
    }
  };
  if (head === "rev" && req.method === "GET") return json({ rev: (await s.get("meta/rev")) || "0" });

  if (head === "profiles" && req.method === "POST" && parts[2] === "claim") {
    // "This is me": succeeds only if no other phone already holds the name.
    if (!id || !/^[A-Za-z0-9_-]{1,40}$/.test(id)) return json({ error: "bad id" }, 400);
    if (!keyHash) return json({ error: "key" }, 400);
    const cur = (await s.get("pf/" + id, { type: "json" })) as Pf | null;
    if (!cur) return json({ error: "not found" }, 404);
    if (cur.k && cur.k !== keyHash) return json({ error: "taken" }, 409);
    if (!cur.k) {
      await s.setJSON("pf/" + id, { ...cur, k: keyHash });
      await bump();
    }
    return json({ ok: true });
  }

  if (head === "profiles" && req.method === "PUT") {
    if (!id || !/^[A-Za-z0-9_-]{1,40}$/.test(id)) return json({ error: "bad id" }, 400);
    const cur = (await s.get("pf/" + id, { type: "json" })) as Pf | null;
    if (cur?.k && cur.k !== keyHash) return json({ error: "taken" }, 409);
    const b = (await req.json().catch(() => ({}))) as Record<string, unknown>;
    const name = str(b.name, 24).trim();
    const photo = String(b.photo ?? "");
    if (!name) return json({ error: "invalid" }, 400);
    if (photo && (!photo.startsWith("data:image/jpeg;base64,") || photo.length > 80000)) return json({ error: "photo" }, 400);
    // "mine" is sent when a phone saves its own profile; a name jotted down for someone else stays unclaimed.
    const k = cur?.k || (b.mine && keyHash ? keyHash : "");
    await s.setJSON("pf/" + id, { name, photo, ...(k ? { k } : {}) });
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
  const sentence = (w: string[]) => (w.length > 1 ? w.slice(0, -1).join(", ") + " and " + w[w.length - 1] : w[0] || "changed it");
  const notifyOthers = async (heading: string, what: string[], evId: string) => {
    const keys = await vapid();
    const who = await whoIs();
    const name = who ? ((await s.get("pf/" + who, { type: "json" })) as { name?: string } | null)?.name : "";
    const payload = JSON.stringify({ title: heading, body: (name || "Someone") + " " + sentence(what), id: evId });
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

  // Automatic dates (bank holidays and the like) cannot be renamed or moved, but their look and list can be changed.
  if (head === "auto" && req.method === "PUT") {
    if (!id || !/^[a-z0-9-]{1,60}$/.test(id)) return json({ error: "bad id" }, 400);
    const b = (await req.json().catch(() => ({}))) as Record<string, unknown>;
    const full = clean({ ...b, title: "x", y: 2000, m: 1, d: 1 });
    if (!full) return json({ error: "invalid" }, 400);
    const was = (await s.get("ao/" + id, { type: "json" })) as Record<string, unknown> | null;
    const now = { color: full.color, icon: full.icon, scene: full.scene, important: full.important, todo: full.todo };
    await s.setJSON("ao/" + id, now);
    const what = listChanges(was, now);
    const listOnly = [...what];
    if (was && ["color", "icon", "scene", "important"].some((k) => String(was[k] ?? "") !== String((now as Record<string, unknown>)[k] ?? ""))) what.push("changed how it looks");
    await log(id, titleFromSlug(id), what);
    if (listOnly.length) context.waitUntil(notifyOthers("Updated: " + titleFromSlug(id), listOnly, id).catch((e) => console.error("notify", e)));
    await bump();
    return json({ ok: true });
  }

  if (head !== "events") return json({ error: "not found" }, 404);

  if (!id && req.method === "GET") {
    // note (at most once a day) that this phone is still in use, so its private events are never treated as lost
    if (keyHash && !(Number(await s.get("seen/" + keyHash)) > Date.now() - 864e5)) await s.set("seen/" + keyHash, String(Date.now()));
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
          const data = (await s.get(b.key, { type: "json" })) as Pf | null;
          if (!data) return null;
          let k = data.k || "";
          // a phone already using a name from before names were tied to phones keeps it
          if (!k && keyHash && meId && b.key === "pf/" + meId) {
            k = keyHash;
            await s.setJSON(b.key, { ...data, k });
            await bump();
          }
          return { name: data.name, photo: data.photo, id: b.key.slice(3), taken: !!k, mine: !!k && k === keyHash };
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
    const activity = (((await s.get("act", { type: "json" })) as Entry[] | null) || [])
      .filter((a) => (!a.owner || a.owner === keyHash) && Date.now() - a.t < KEEP)
      .map(({ k, owner, ...rest }) => ({ ...rest, mine: !!keyHash && k === keyHash }));
    return json({ rev: (await s.get("meta/rev")) || "0", events, profiles, auto, activity, hasAdmin: !!cfg.adminHash, admin: isAdmin });
  }

  if (!id || !/^[A-Za-z0-9_-]{1,40}$/.test(id)) return json({ error: "bad id" }, 400);

  const prev = (await s.get("ev/" + id, { type: "json" })) as (Record<string, unknown> & { owner?: string }) | null;
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
    const what = describe(prev, data);
    await log(id, String(data.title), what, data.owner as string | undefined);
    await bump();
    // Tell the other phone about new shared events and changes to them; never about private ones.
    if (!data.priv && !prev?.owner && what.length)
      context.waitUntil(notifyOthers((prev ? "Updated: " : "New countdown: ") + data.title, what, id).catch((e) => console.error("notify", e)));
    return json({ ok: true });
  }
  if (req.method === "DELETE") {
    await s.delete("ev/" + id);
    if (prev) await log(id, String(prev.title || ""), ["removed this event"], prev.owner);
    await bump();
    if (prev && !prev.owner) context.waitUntil(notifyOthers("Removed: " + String(prev.title || ""), ["removed this event"], "").catch((e) => console.error("notify", e)));
    return json({ ok: true });
  }
  return json({ error: "method" }, 405);
};

export const config: Config = {
  path: ["/api", "/api/*"],
  // Slows down passcode guessing; normal use is one small check every 6 seconds per phone.
  rateLimit: { windowLimit: 90, windowSize: 60, aggregateBy: ["ip", "domain"] },
};

// ZipZapBags payment server (Cloudflare Worker)
// Creates Razorpay orders with the amount calculated HERE (not in the customer's browser)
// and verifies the payment signature after the customer pays.
//
// Variables to set in Cloudflare (Settings -> Variables and Secrets):
//   RAZORPAY_KEY_ID      your Razorpay Key ID            (text)
//   RAZORPAY_KEY_SECRET  your Razorpay Key Secret        (Secret / encrypted)
//   PRODUCTS_URL         https://YOUR-USERNAME.github.io/YOUR-REPO/products.json
//   ALLOWED_ORIGIN       https://YOUR-USERNAME.github.io   (no trailing slash)

class HttpError extends Error { constructor(m, s = 400) { super(m); this.status = s; } }

const cors = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
});
const json = (obj, status, origin) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...cors(origin) } });

async function createOrder(body, env) {
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET || !env.PRODUCTS_URL) throw new HttpError("Payment server is not set up yet.", 500);
  const items = Array.isArray(body.items) ? body.items : [];
  if (!items.length || items.length > 30) throw new HttpError("Your bag is empty.");

  const res = await fetch(env.PRODUCTS_URL, { cf: { cacheTtl: 30 } });
  if (!res.ok) throw new HttpError("Could not load the price list.", 502);
  const cat = await res.json();
  const byId = new Map(cat.products.map((p) => [p.id, p]));

  let sub = 0;
  const qtyById = {};
  for (const it of items) {
    const p = byId.get(Number(it.id));
    const q = Number(it.q);
    if (!p || !Number.isInteger(q) || q < 1 || q > 20) throw new HttpError("An item in your bag is no longer available.");
    qtyById[p.id] = (qtyById[p.id] || 0) + q;
    sub += p.price * q;
  }
  for (const id in qtyById) {
    const p = byId.get(Number(id));
    if (p.stock < qtyById[id]) throw new HttpError(p.stock ? "Only " + p.stock + " left of " + p.name + "." : p.name + " is sold out.");
  }

  let cd = 0;
  const c = body.coupon ? cat.coupons[String(body.coupon).toUpperCase()] : null;
  if (c && sub >= c.min) cd = c.t === "pct" ? (sub * c.v) / 100 : c.v;
  const ship = sub >= cat.shipFreeAbove ? 0 : cat.shipFee;
  const gw = body.gift ? cat.giftFee : 0;
  const total = sub - cd + ship + gw;
  const amount = Math.round(total * 100);
  if (!(amount >= 100)) throw new HttpError("Invalid order amount.");

  const cu = body.cust || {};
  const notes = {
    name: String(cu.name || "").slice(0, 100), phone: String(cu.phone || "").slice(0, 15), email: String(cu.email || "").slice(0, 100),
    address: [cu.addr, cu.city, cu.state, cu.pin].filter(Boolean).join(", ").slice(0, 250),
    items: items.map((i) => (byId.get(Number(i.id)) || {}).name + " x" + i.q + " " + (i.col || "")).join("; ").slice(0, 250),
    coupon: c ? String(body.coupon).toUpperCase() : "", gift: body.gift ? "yes" : "no", gift_note: String(body.giftMsg || "").slice(0, 200),
  };
  const r = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Basic " + btoa(env.RAZORPAY_KEY_ID + ":" + env.RAZORPAY_KEY_SECRET) },
    body: JSON.stringify({ amount, currency: "INR", receipt: "ZZB" + Date.now().toString().slice(-9), notes }),
  });
  const o = await r.json().catch(() => ({}));
  if (!r.ok || !o.id) throw new HttpError((o.error && o.error.description) || "Could not start the payment.", 502);
  return { order_id: o.id, amount: o.amount, currency: o.currency };
}

async function verify(body, env) {
  const { razorpay_order_id: oid, razorpay_payment_id: pid, razorpay_signature: sig } = body || {};
  if (!oid || !pid || !sig) throw new HttpError("Missing payment details.");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.RAZORPAY_KEY_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(oid + "|" + pid));
  const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  let diff = hex.length ^ String(sig).length;
  for (let i = 0; i < hex.length; i++) diff |= hex.charCodeAt(i) ^ String(sig).charCodeAt(i);
  if (diff !== 0) throw new HttpError("Payment could not be verified.", 400);
  return { ok: true };
}

export default {
  async fetch(req, env) {
    const origin = env.ALLOWED_ORIGIN || "*";
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });
    const reqOrigin = req.headers.get("Origin");
    if (env.ALLOWED_ORIGIN && reqOrigin && reqOrigin !== env.ALLOWED_ORIGIN) return json({ error: "Not allowed" }, 403, env.ALLOWED_ORIGIN);
    if (req.method !== "POST") return json({ error: "Use POST" }, 405, origin);
    try {
      const path = new URL(req.url).pathname;
      if (path === "/create-order") return json(await createOrder(await req.json(), env), 200, origin);
      if (path === "/verify") return json(await verify(await req.json(), env), 200, origin);
      return json({ error: "Not found" }, 404, origin);
    } catch (e) {
      return json({ error: e.message || "Server error" }, e.status || 500, origin);
    }
  },
};

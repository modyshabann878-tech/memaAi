// Cloudflare Worker: الـ Backend بتاع "memai: رسّيني على زرعتي" (Gemini)
// يحتاج: Secrets: GEMINI_API_KEY و ADMIN_KEY، وKV Namespace مربوط باسم CODES،
// ومتغيرات اختيارية: ALLOWED_ORIGIN و GEMINI_MODEL.

const FREE_LIMIT = 2; // عدد الفيديوهات المجانية لكل جهاز (IP)

const TONES = {
  friendly: "ودودة وقريبة من القارئ",
  professional: "رسمية ومحترفة",
  excited: "حماسية ومشجعة",
  funny: "خفيفة وساخرة بدون إساءة",
};

const json = (obj, status, cors) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...cors },
  });

const ALPHA = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
function newCode() {
  const a = new Uint8Array(8);
  crypto.getRandomValues(a);
  return Array.from(a, x => ALPHA[x % ALPHA.length]).join("");
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
// يتحقق من باسورد الأدمن (Secret اسمه ADMIN_KEY) ويقفل بعد 5 محاولات غلط في الساعة
async function auth(key, env, req) {
  const fk = "fail:" + (req.headers.get("CF-Connecting-IP") || "x");
  const f = parseInt((await env.CODES.get(fk)) || "0", 10);
  if (f >= 5) return "locked";
  if (env.ADMIN_KEY && typeof key === "string" && same(key, env.ADMIN_KEY)) return "ok";
  await env.CODES.put(fk, String(f + 1), { expirationTtl: 3600 });
  return "bad";
}

// CORS: ALLOWED_ORIGIN ممكن تبقى أكتر من رابط مفصولين بفاصلة، والرد بيرجع بالرابط المطابق
function corsFor(req, env) {
  const list = String((env && env.ALLOWED_ORIGIN) || "https://modyshabann878-tech.github.io").split(",").map(s => s.trim()).filter(Boolean);
  const o = req && req.headers ? req.headers.get("Origin") : null;
  return {
    "Access-Control-Allow-Origin": list.includes(o) ? o : list[0],
    "Vary": "Origin",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
  };
}

// تنضيف الصورة: يشيل أي data:image/...;base64, ومسافات، ويحوّل base64 الـ URL-safe، ويكمّل الـ padding،
// ويتأكد من نوعها الحقيقي من أول بايتات (jpeg أو png أو webp)، وأي حاجة تانية بتتتجاهل
function normImg(x) {
  if (typeof x !== "string") return null;
  const m = /^data:image\/[a-z0-9.+-]+;base64,/i.exec(x);
  let data = (m ? x.slice(m[0].length) : x).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (data.length < 100 || data.length > 1600000 || data.length % 4 === 1 || !/^[A-Za-z0-9+/]+$/.test(data)) return null;
  while (data.length % 4) data += "=";
  let head;
  try { head = atob(data.slice(0, 16)); } catch { return null; }
  const mime = head.startsWith("\xFF\xD8\xFF") ? "image/jpeg"
    : head.startsWith("\x89PNG") ? "image/png"
    : (head.startsWith("RIFF") && head.slice(8, 12) === "WEBP") ? "image/webp" : null;
  return mime ? { mime, data } : null;
}

// إصلاح JSON: سطور جديدة وtabs جوه النصوص، والفواصل الزيادة قبل } أو ]
function repairJson(t) {
  let o = "", str = false, esc = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (str) {
      if (esc) { o += c; esc = false; }
      else if (c === "\\") { o += c; esc = true; }
      else if (c === '"') { o += c; str = false; }
      else if (c === "\n") o += "\\n";
      else if (c === "\r") o += "";
      else if (c === "\t") o += "\\t";
      else if (c < " ") o += " ";
      else o += c;
    } else if (c === '"') { o += c; str = true; }
    else if (c === ",") {
      let j = i + 1;
      while (j < t.length && /\s/.test(t[j])) j++;
      if (t[j] !== "}" && t[j] !== "]") o += c;
    } else o += c;
  }
  return o;
}

const handler = {
  async fetch(req, env) {
    const cors = corsFor(req, env);
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });
    if (!env.CODES) return json({ error: "server", reason: "no_kv_binding" }, 500, cors);
    if (req.method === "GET") {
      const site = (await env.CODES.get("site")) || "{}";
      return new Response(site, { headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors } });
    }
    if (req.method !== "POST") return json({ error: "server" }, 405, cors);

    const rawText = await req.text(); // الـ body بيتقرا مرة واحدة بس هنا
    if (rawText.length > 8000000) return json({ error: "too_big" }, 413, cors);
    let b;
    try { b = JSON.parse(rawText); } catch { return json({ error: "server", reason: "bad_request_body" }, 400, cors); }
    if (!b || typeof b !== "object") return json({ error: "server", reason: "bad_request_body" }, 400, cors);

    const code = String(b.code || "").trim().toUpperCase();
    const codeKey = "code:" + code;

    // أوامر الأدمن
    if (b.action) {
      const a = await auth(b.key, env, req);
      if (a === "locked") return json({ error: "locked" }, 429, cors);
      if (a !== "ok") return json({ error: "bad_key" }, 401, cors);
      if (b.action === "verify") return json({ ok: true }, 200, cors);
      if (b.action === "save_content") {
        const s = JSON.stringify(b.content || {});
        if (s.length > 100000 || !b.content || !Array.isArray(b.content.plans)) return json({ error: "server" }, 400, cors);
        await env.CODES.put("site", s);
        return json({ ok: true }, 200, cors);
      }
      if (b.action === "create_code") {
        const n = Math.max(1, Math.min(1000, parseInt(b.remaining, 10) || 20));
        const days = parseInt(b.days, 10) || 0;
        const c = newCode();
        const r = { remaining: n, used: 0, copied: 0, created: Date.now() };
        if (days > 0) r.expires = Date.now() + days * 86400000;
        await env.CODES.put("code:" + c, JSON.stringify(r));
        return json({ code: c }, 200, cors);
      }
      if (b.action === "list_codes") {
        const l = await env.CODES.list({ prefix: "code:", limit: 50 });
        const codes = [];
        for (const k of l.keys) {
          const r = await env.CODES.get(k.name, "json");
          if (r) codes.push({ code: k.name.slice(5), ...r });
        }
        return json({ codes }, 200, cors);
      }
      return json({ error: "server" }, 400, cors);
    }

    // تسجيل عملية النسخ (لشرط الاسترجاع)
    if (b.event === "copy") {
      if (code) {
        const rec = await env.CODES.get(codeKey, "json");
        if (rec) {
          rec.copied = (rec.copied || 0) + 1;
          await env.CODES.put(codeKey, JSON.stringify(rec));
        }
      }
      return json({ ok: true }, 200, cors);
    }

    const clip = (v, n) => String(v == null ? "" : v).trim().slice(0, n);
    const p = b.profile && typeof b.profile === "object" ? b.profile : {};
    const q = clip(b.question, 1500);
    const imgs = (Array.isArray(b.images) ? b.images : []).slice(0, 4).map(normImg).filter(Boolean);
    if (!q && !p.crop && !imgs.length) return json({ error: "need_info" }, 400, cors);

    // التحقق من الحصة قبل أي استدعاء مدفوع
    let rec = null, freeKey = null, used = 0;
    if (code) {
      rec = await env.CODES.get(codeKey, "json");
      if (!rec) return json({ error: "code_invalid" }, 403, cors);
      if (rec.expires && Date.now() > rec.expires) return json({ error: "code_invalid" }, 403, cors);
      if ((rec.remaining || 0) <= 0) return json({ error: "no_quota" }, 403, cors);
    } else {
      const ip = req.headers.get("CF-Connecting-IP") || "unknown";
      freeKey = "free:" + ip;
      used = parseInt((await env.CODES.get(freeKey)) || "0", 10);
      if (used >= FREE_LIMIT) return json({ error: "free_limit" }, 403, cors);
    }

    const STAGE = { planning: "لسه هيزرع", early: "زرع من قريب", mid: "في نص الزرعة", late: "قرب الحصاد" };
    const rows = [["اسم الأرض", "name"], ["المحصول", "crop"], ["المنطقة", "region"], ["المساحة", "area"], ["وحدة المساحة", "unit"], ["حالة الزراعة", "stage"], ["تاريخ الزراعة", "date"], ["طريقة الري", "irr"], ["التربة", "soil"], ["أداة الرش", "tool"], ["سعة خزان الرش (لتر)", "tank"], ["ماتور الري", "pump"]];
    const prof = rows.map(([a, k]) => { const v = k === "stage" ? (STAGE[p[k]] || "") : clip(p[k], 100); return a + ": " + (v || "غير محدد"); }).join("\n");
    const logs = (Array.isArray(b.logs) ? b.logs.slice(-15) : []).map(l => "- " + clip(l.d, 10) + " | " + clip(l.t, 20) + " | " + clip(l.x, 200)).join("\n");
    const ctx = "ملف الزرعة:\n" + prof + "\n\nسجل الأعمال (من الأقدم للأحدث):\n" + (logs || "لا يوجد") + "\n\nسؤال أو وصف المزارع:\n" + (q || "لم يكتب شيئاً") + "\n\nتاريخ اليوم: " + new Date().toISOString().slice(0, 10) + (imgs.length ? "\n(مرفق " + imgs.length + " صورة)" : "");

    const system =
      "أنت مرشد زراعي لمزارعين في مصر، تكتب بالعامية المصرية البسيطة وبجمل قصيرة. هتاخد ملف زرعة وسجل أعمال وسؤال وصور، وتديهم تقييم وخطة عملية. " +
      "لو المزارع لسه هيزرع أو في أول الزراعة، اديله خطوات مرتبة بالمواعيد (تجهيز، زراعة، ري، تسميد، مكافحة). لو الزرعة في النص، ابني على السجل ومتكررش اللي اتعمل. " +
      "قواعد صارمة: (1) لو الصورة مش واضحة أو المعلومات ناقصة، قول كده وحط الناقص في missing_info ومتجزمش بتشخيص، وخلي confidence منخفضة. " +
      "(2) في الرش اذكر المادة الفعالة والغرض، مش اسم تجاري بس، وخلي الجرعة في حدود المعتاد على ملصقات المنتجات المسجلة في مصر، ولو مش متأكد من رقم سيب الحقل null واكتب في notes إنه يراجع الملصق. " +
      "(3) متنصحش بمبيدات محظورة أو شديدة الخطورة. (4) اذكر فترة الأمان قبل الحصاد phi_days لو تعرفها. (5) اراعي طريقة الري وأداة الرش: التسميد مع التنقيط يتحسب للفدان method=fertigation، والرش الورقي يتحسب لكل 100 لتر ماء. " +
      "(6) متحسبش إجمالي الكميات بنفسك، التطبيق بيحسبها من الأرقام اللي تديها. (7) متقولش إنك بديل للمهندس الزراعي. " +
      "رد بـ JSON صالح فقط بالمفاتيح دي بالظبط: summary (نص)، confidence (عالية أو متوسطة أو منخفضة)، actions (قائمة نصوص)، " +
      "spray (قائمة كائنات: purpose, active_ingredient, method بقيمة foliar أو fertigation, dose_per_100l رقم أو null, dose_per_feddan رقم أو null, unit بقيمة جم أو سم3, water_l_per_feddan رقم أو null, timing, phi_days رقم أو null, notes)، " +
      "schedule (قائمة كائنات: when, what)، warnings (قائمة نصوص)، missing_info (قائمة نصوص). لو مفيش رش مطلوب خلي spray قائمة فاضية.";

    if (!env.GEMINI_API_KEY) return json({ error: "server", reason: "no_gemini_key" }, 500, cors);

    // الموديلات بالترتيب. بيكمّل للي بعده لو 404 (متوقف) أو 429 أو 5xx. أخطاء المفتاح أو الطلب (400/401/403) مبتتحلش بموديل تاني فبتتوقف فوراً.
    const models = [...new Set([env.GEMINI_MODEL, "gemini-2.5-flash", "gemini-3.5-flash-lite", "gemini-flash-latest"].filter(Boolean))];
    const mkBody = short => JSON.stringify({
      systemInstruction: { parts: [{ text: system + (short ? " اختصر الرد جداً: حد أقصى 4 عناصر في actions وكائنين في spray وجمل قصيرة." : "") }] },
      contents: [{ role: "user", parts: [{ text: ctx }, ...imgs.map(i => ({ inline_data: { mime_type: i.mime, data: i.data } }))] }],
      generationConfig: { responseMimeType: "application/json", maxOutputTokens: 8192 },
    });
    // بترجّع { raw, finish } لو نجح، أو { fail, detail } مع سبب دقيق لكل نوع فشل
    const callGemini = async body => {
      let res = null;
      for (const model of models) {
        try {
          res = await fetch("https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent", {
            method: "POST",
            headers: { "Content-Type": "application/json", "x-goog-api-key": env.GEMINI_API_KEY },
            body,
          });
        } catch (e) { console.error("network", model, String(e)); return { fail: "network", detail: String(e).slice(0, 150) }; }
        if (![404, 429, 500, 503].includes(res.status)) break;
        console.error("model skipped:", model, res.status);
      }
      if (!res.ok) {
        const t = await res.text();
        let detail = "";
        try { detail = (JSON.parse(t).error || {}).message || ""; } catch {}
        console.error("gemini", res.status, t.slice(0, 500));
        return { fail: "gemini_" + res.status, detail: detail.slice(0, 200) };
      }
      let d;
      try { d = await res.json(); } catch (e) { return { fail: "bad_response", detail: String(e).slice(0, 100) }; }
      const c = d.candidates && d.candidates[0];
      if (!c) return { fail: "blocked", detail: String((d.promptFeedback && d.promptFeedback.blockReason) || "no_candidates") };
      return { raw: ((c.content && c.content.parts) || []).map(x => x.text || "").join(""), finish: c.finishReason || "" };
    };
    // بيقص من أول { لآخر } عشان يتخطى أي كلام زيادة، وبعدين parse
    const parseJson = raw => {
      const t = raw.replace(/```json|```/g, "");
      const s = t.indexOf("{"), e = t.lastIndexOf("}");
      if (s < 0 || e <= s) throw new Error("no_json");
      const body = t.slice(s, e + 1);
      try { return JSON.parse(body); } catch { return JSON.parse(repairJson(body)); }
    };

    let r = await callGemini(mkBody(false));
    let out = null;
    if (r.raw != null) {
      try { out = parseJson(r.raw); }
      catch (e) {
        console.error("json", r.finish, String(e), r.raw.slice(-200));
        r = await callGemini(mkBody(true)); // محاولة تانية بطلب مختصر
        if (r.raw != null) {
          try { out = parseJson(r.raw); }
          catch (e2) { return json({ error: "server", reason: r.finish === "MAX_TOKENS" ? "truncated" : "bad_json", detail: "finish=" + r.finish }, 502, cors); }
        }
      }
    }
    if (!out) return json({ error: "server", reason: r.fail || "empty", detail: r.detail || "" }, 502, cors);
    if (typeof out.summary !== "string") return json({ error: "server", reason: "no_summary" }, 502, cors);

    // الخصم بعد النجاح فقط
    let remaining;
    if (rec) {
      rec.remaining -= 1;
      rec.used = (rec.used || 0) + 1;
      await env.CODES.put(codeKey, JSON.stringify(rec));
      remaining = rec.remaining;
    } else {
      await env.CODES.put(freeKey, String(used + 1), { expirationTtl: 60 * 60 * 24 * 30 });
      remaining = FREE_LIMIT - (used + 1);
    }

    const arr = v => (Array.isArray(v) ? v : []);
    return json({
      summary: out.summary,
      confidence: out.confidence || "",
      actions: arr(out.actions),
      spray: arr(out.spray),
      schedule: arr(out.schedule),
      warnings: arr(out.warnings),
      missing_info: arr(out.missing_info),
      remaining,
    }, 200, cors);
  },
};

// أي خطأ مش متوقع بيرجع JSON واضح بهيدرز CORS، بدل صفحة خطأ بتظهر في المتصفح كأنها مشكلة CORS
export default {
  async fetch(req, env, ctx) {
    try { return await handler.fetch(req, env, ctx); }
    catch (e) {
      console.error("uncaught", String(e));
      return new Response(JSON.stringify({ error: "server", reason: "exception", detail: String(e).slice(0, 150) }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsFor(req, env) },
      });
    }
  },
};

// worker.js - Bot en Cloudflare Workers
// Cron: cada minuto procesa 1 cuenta (o todas las pendientes si hay CPU)
// Fetch: panel web + API
import { DurableObject } from "cloudflare:workers";
import { MitosClient } from "./mito_client.js";

const KV_KEYS = {
  accounts: "utopia_accounts",
  plans: "utopia_plans",
  plansMap: "utopia_plans_map",  // deviceId -> plan (separado: el cron no lo toca)
  pem: "utopia_pem",
  cursor: "utopia_cursor",
  open: "utopia_open_cursor",    // cursor de cofres (separado: el cron no lo pisa)
};

// Lee el mapa de planes (deviceId -> planName). Autoridad: solo lo escribe el
// usuario desde el panel; el cron nunca lo pisa (evita la race condition del KV).
async function readPlansMap(env) {
  const m = await env.UTOPIA_KV.get(KV_KEYS.plansMap);
  if (!m) return {};
  try { return JSON.parse(m); } catch { return {}; }
}

// Aplica el mapa de planes sobre las cuentas (los planes del mapa ganan).
function applyPlansMap(accounts, plansMap) {
  for (const a of accounts) {
    if (plansMap[a.deviceId]) a.plan = plansMap[a.deviceId];
  }
  return accounts;
}

// Recetas reales del laboratorio: id -> nombre y salida base por craft.
// Estos ids son distintos de los ids de compra de la Shop.
const LAB_RECIPES = {
  1:  { name: "Mythical Speed Potion", qty: 3 },
  2:  { name: "Superior Portal Glue", qty: 3 },
  3:  { name: "Speed Shot", qty: 3 },
  4:  { name: "Speed Anticellular Shield", qty: 3 },
  5:  { name: "Gravity Speed Potion", qty: 3 },
  6:  { name: "Powerful Chainsaw", qty: 5 },
  7:  { name: "Portal Shield Armor", qty: 3 },
  8:  { name: "Legendary Speed Potion", qty: 2 },
  9:  { name: "Legendary Gravity Potion", qty: 2 },
  10: { name: "Legendary Blink", qty: 2 },
  13: { name: "Super Glue Potion", qty: 3 },
  16: { name: "Superior Portal Gun", qty: 3 },
  19: { name: "Anticellular Armor", qty: 3 },
  22: { name: "Superior Blink", qty: 3 },
  23: { name: "Bubble Gun", qty: 5 },
  24: { name: "Antiviral Portal Gun", qty: 3 },
  25: { name: "Superior Immunity Shield", qty: 3 },
  26: { name: "Superior Gravity Blink", qty: 3 },
};

// Alias de nombres: el lab 5 produce "Gravity Speed Potion" pero algunos planes
// antiguos lo guardaron como "Speed & Gravity Potion". El lab 2 produce
// "Superior Portal Glue" pero planes viejos guardaron "Powerful Portal Glue".
const LAB_NAME_ALIASES = {
  "speed & gravity potion": 5,
  "powerful portal glue": 2,
};

function labIdForName(name) {
  const clean = String(name || "").replace(/^\d+x\s*/, "").trim();
  for (const [id, recipe] of Object.entries(LAB_RECIPES)) {
    if (clean === recipe.name) return parseInt(id);
  }
  const alias = LAB_NAME_ALIASES[clean.toLowerCase()];
  if (alias) return alias;
  return -1;
}

function labRecipeForName(name) {
  const clean = String(name || "").replace(/^\d+x\s*/, "").trim();
  for (const recipe of Object.values(LAB_RECIPES)) {
    if (clean === recipe.name) return recipe;
  }
  const alias = LAB_NAME_ALIASES[clean.toLowerCase()];
  if (alias) return LAB_RECIPES[alias];
  return null;
}

// Ingredientes que requiere cada receta del lab: {shopId, cantidad}
// (port de kLabIngredients de loginbridge.cpp; shopId=0 => lab-crafted, no se compra)
const LAB_INGREDIENTS = {
  2:  [{ shopId: 98, qty: 2 }, { shopId: 274, qty: 4 }],   // Superior Portal Glue
  3:  [{ shopId: 156, qty: 3 }, { shopId: 97, qty: 3 }],   // Speed Shot
  4:  [{ shopId: 156, qty: 3 }, { shopId: 147, qty: 3 }],   // Speed Anticellular Shield
  5:  [{ shopId: 156, qty: 2 }, { shopId: 101, qty: 4 }],   // Speed & Gravity Potion
  6:  [{ shopId: 320, qty: 2 }, { shopId: 213, qty: 3 }],   // Powerful Chainsaw
  7:  [{ shopId: 147, qty: 3 }, { shopId: 274, qty: 3 }],   // Portal Shield Armor
  8:  [{ shopId: 97, qty: 4 }],                              // Legendary Speed Potion
  9:  [{ shopId: 101, qty: 4 }],                             // Legendary Gravity Potion
  10: [{ shopId: 104, qty: 4 }],                             // Legendary Blink
  24: [{ shopId: 145, qty: 3 }, { shopId: 274, qty: 3 }],   // Antiviral Portal Gun
  25: [{ shopId: 147, qty: 3 }, { shopId: 145, qty: 3 }],   // Superior Immunity Shield
  // 1, 13, 16, 19, 22, 23: sin ingredientes (free); 26: lab-only
};

function normalizeHistoryEntry(entry) {
  const recipe = labRecipeForName(entry?.name);
  if (!recipe) return entry;
  const hasQty = Object.prototype.hasOwnProperty.call(entry, "qty");
  let crafts = Number(entry.crafts || 0);
  if (crafts < 1) crafts = hasQty ? 1 : Math.max(1, Number(entry.count || 0));
  let perCraft = Number(entry.qty || 0);
  if (!hasQty || perCraft < 1) {
    perCraft = recipe.qty;
  } else {
    const multiplier = Math.max(1, Math.min(3, Math.round(perCraft / recipe.qty)));
    perCraft = recipe.qty * multiplier;
  }
  return { ...entry, count: perCraft * crafts, qty: perCraft, crafts };
}

function normalizeAccountHistory(account) {
  const history = Array.isArray(account.craftHistory) ? account.craftHistory : [];
  const normalized = history.map(normalizeHistoryEntry);
  const total = normalized.reduce((sum, entry) => sum + Number(entry.count || 0), 0);
  account.craftHistory = normalized;
  account.craftCount = total;
  return account;
}

function recordCraft(account, potionName) {
  const recipe = labRecipeForName(potionName);
  if (!recipe) return;
  normalizeAccountHistory(account);
  const multiplier = Math.max(1, Math.min(3, Number(account.labMultiplier || 1)));
  const qty = recipe.qty * multiplier;
  const cleanName = String(potionName).replace(/^\d+x\s*/, "").trim();
  let entry = account.craftHistory.find(item =>
    String(item.name || "").replace(/^\d+x\s*/, "").trim() === cleanName);
  if (!entry) {
    entry = { name: cleanName, count: 0, crafts: 0, qty };
    account.craftHistory.push(entry);
  }
  entry.count = Number(entry.count || 0) + qty;
  entry.crafts = Number(entry.crafts || 0) + 1;
  entry.qty = qty;
  account.craftCount = Number(account.craftCount || 0) + qty;
  account.lastCraftAt = new Date().toISOString();
}

function updateLabSummary(account, slots) {
  const list = Array.isArray(slots) ? slots : [];
  const lockedSlots = list.filter(s => String(s?.status || s?.craft || "").toLowerCase() === "locked").length;
  account.labSlots = Math.max(0, list.length - lockedSlots);
  account.lockedSlots = lockedSlots;
  account.slots = list;
  account.slotsScannedAt = new Date().toISOString();
  // AUTO-DETECCION del multiplicador real: el server devuelve la cantidad real
  // de cada craft en el nombre (p.ej. "9x Super Glue Potion" con triplicador).
  // Si el multiplicador (2-3 dias) expira, el server vuelve a "3x" y aqui se
  // revierte a x1 automaticamente en el proximo scan.
  const recipeQty = { "Mythical Speed Potion": 3, "Superior Portal Glue": 3, "Speed Shot": 3, "Speed Anticellular Shield": 3, "Gravity Speed Potion": 3, "Powerful Chainsaw": 5, "Portal Shield Armor": 3, "Legendary Speed Potion": 2, "Legendary Gravity Potion": 2, "Legendary Blink": 2, "Super Glue Potion": 3, "Superior Portal Gun": 3, "Anticellular Armor": 3, "Superior Blink": 3, "Bubble Gun": 5, "Antiviral Portal Gun": 3, "Superior Immunity Shield": 3, "Superior Gravity Blink": 3 };
  let detectedMult = 0;
  for (const s of list) {
    const m = String(s?.name || "").match(/^(\d+)x\s*(.+)$/);
    if (!m) continue;
    const qty = parseInt(m[1]);
    const base = recipeQty[m[2].trim()] || 0;
    if (qty > 0 && base > 0) detectedMult = Math.max(detectedMult, Math.min(3, Math.max(1, Math.round(qty / base))));
  }
  if (detectedMult > 0 && detectedMult !== Number(account.labMultiplier || 1)) {
    account.labMultiplier = detectedMult;
    account.labMultiplierAutoAt = new Date().toISOString();
  }
  // timestamp absoluto del fin de cada craft: el cron lo usa para saber CUANDO
  // debe actuar sin consultar al server (una pocion tarda 3.5h-18h)
  const scannedAt = Date.parse(account.slotsScannedAt) || Date.now();
  for (const s of list) {
    if (s.time > 0) s.endAt = scannedAt + Number(s.time) * 1000;
    else s.endAt = 0;
  }
}

async function kvGet(env, key, def) {
  const v = await env.UTOPIA_KV.get(key);
  if (!v) return def;
  try { return JSON.parse(v); } catch { return def; }
}

async function kvSet(env, key, val) {
  await env.UTOPIA_KV.put(key, JSON.stringify(val));
}

// ============ BOT ============
async function openDailyChest(c, name, log) {
  const news = await c.news();
  const chest = (news.data || {}).chest || {};
  let chestId = chest.id || -1;
  if (chestId <= 0) {
    const ach = await c.achievements();
    let best = null;
    for (const a of (ach.data || {}).list || []) {
      if ((a.current || 0) < (a.total || 1) || a.awarded) continue;
      if (a.index === 2297 || a.index === 2295) { best = a; break; }
    }
    if (best) {
      const gr = await c.getReward(best.id);
      log.push(`${name}: getreward idx=${best.index} -> ${gr.result}`);
      const news2 = await c.news();
      chestId = ((news2.data || {}).chest || {}).id || -1;
    }
  }
  if (chestId > 0) {
    const oc = await c.openChest(chestId);
    const rewards = ((oc.data || {}).rewards || []).map(r => ({
      type: r.type || "",
      sprite: r.sprite || "",
      amount: Number(r.amount || 1),
      title: r.title || r.type || "Reward",
    }));
    const rewardText = rewards.map(r => `${r.amount}x ${r.title}`).join(", ");
    log.push(`${name}: CHEST ${oc.result} -> ${rewardText} coins=${(oc.data || {}).coins}`);
    return {
      ok: oc.result === "ok",
      chestId,
      rewards,
      coins: (oc.data || {}).coins ?? null,
      error: oc.result === "ok" ? "" : (oc.message || "open chest failed"),
    };
  }
  return { ok: false, chestId: -1, rewards: [], coins: null, error: "no chest available" };
}

async function processAccount(acc, pem, plans, log, saveAccountsFn) {
  normalizeAccountHistory(acc);
  const name = acc.name || "?";
  const c = new MitosClient(acc.deviceId, pem);
  // reutilizar la sesion guardada: solo login completo cuando el server la rechaza
  const sess = await c.loginIfNeeded(acc.sessionKey, acc.magic);
  if (sess && sess.sessionKey) {
    acc.sessionKey = sess.sessionKey;
    acc.magic = sess.magic;
    acc.sessionAt = new Date().toISOString();
  }
  const real = await c.fetchAccount();
  if (real.name) { acc.name = real.name; }
  if (real.coins != null) { acc.coins = real.coins; }
  if (saveAccountsFn) await saveAccountsFn();

  // NOTA: el cron NO abre cofres. Los cofres solo se abren manualmente
  // desde el panel (OPEN CHEST). El loop solo vigila el laboratorio.
  const plan = acc.plan || "Unassigned";
  const planDef = (plans || []).find(p => p.name === plan);
  if (!planDef || !planDef.loop) {
    if (saveAccountsFn) await saveAccountsFn();
    return {};
  }

  const lab = await c.laboratory();
  const slots = (lab.data || {}).slots || [];
  updateLabSummary(acc, slots);

  // 1) slots TERMINADOS (craft=ready con pocion): recoger
  // 2) slots LIBRES (vacio, sin pocion): rellenar con el plan
  const planSlots = planDef.slots || [];
  const picked = [];
  const scanAge = acc.slotsScannedAt ? (Date.now() - Date.parse(acc.slotsScannedAt)) / 1000 : 0;
  for (const s of slots) {
    // poción terminada: craft=ready O contador agotado (time <= 0 real)
    // un slot ready sin nombre tambien debe recogerse (el server a veces lo
    // devuelve sin name); si falla el pick, no es trabajo pendiente eterno
    const realTime = Number(s.time) - scanAge;
    const finished = s.craft === "ready" || (realTime <= 0 && s.name);
    if (finished && s.index >= 0) {
      try {
        await c.pick(s.index);
        picked.push(s.index);
        log.push(`${name}: PICK slot ${s.index} (${s.name || "ready"})`);
      } catch (e) {
        log.push(`${name}: pick error slot ${s.index}: ${String(e).slice(0, 50)}`);
      }
    }
  }
  const freeSlots = slots.filter(s =>
    s.index >= 0 &&
    s.craft !== "crafting" &&
    !s.name &&
    String(s.status || "").toLowerCase() !== "locked");
  const toFill = [...new Set([...picked, ...freeSlots.map(s => s.index)])];

  // AUTOBUY: SOLO cuando hay slots que rellenar (como el PC: compra los
  // ingredientes de las pociones que realmente se van a craftear ahora)
  if (planDef.autobuy && toFill.length > 0) {
    try {
      const potionsToCraft = toFill.map(slot => planSlots[slot]).filter(Boolean);
      const subPlan = { slots: potionsToCraft };
      await autobuyIngredients(c, subPlan, log);
      if (c._lastCoins != null) acc.coins = c._lastCoins;
      if (saveAccountsFn) await saveAccountsFn();
    } catch (e) {
      log.push(`${name}: autobuy error: ${String(e).slice(0, 60)}`);
    }
  }

  for (const slot of toFill) {
    const potionName = planSlots[slot];
    if (!potionName) continue;
    const itemId = labIdForName(potionName);
    if (itemId <= 0) continue;
    // reutilizar la sesion ya autenticada de `c`; relogin SOLO si caduco
    let cr = null;
    try {
      cr = await c.craft(slot, itemId);
    } catch (e) {
      await c.login();
      cr = await c.craft(slot, itemId);
    }
    log.push(`${name}: CRAFT slot ${slot} ${potionName} -> ${cr && cr.result}`);
    if (cr && cr.result === "ok") recordCraft(acc, potionName);
    await new Promise(r => setTimeout(r, 400));
  }
  // coins reales tras crafts/autobuy (balance actual del server)
  if (toFill.length > 0 || (planDef.autobuy)) {
    try {
      const real = await c.fetchAccount();
      if (real.coins != null) acc.coins = real.coins;
    } catch (e) {}
  }
  if (saveAccountsFn) await saveAccountsFn();
  return {};
}

// Compra los ingredientes faltantes del plan y devuelve el resumen
async function autobuyIngredients(c, planDef, log) {
  const planSlots = planDef.slots || [];
  const labIds = [];
  const names = [];
  for (const s of planSlots) {
    const id = labIdForName(s);
    if (id > 0) { labIds.push(id); names.push(s); }
  }
  if (labIds.length === 0) return;
  let stock = {};
  let multiples = {};
  try { stock = await c.potionStock(); } catch (e) {}
  try { multiples = await c.storeMultiples(); } catch (e) {}

  // calcular faltantes por receta del plan
  const missing = {}; // shopId -> cuantos faltan
  for (const labId of labIds) {
    const ings = LAB_INGREDIENTS[labId];
    if (!ings) continue;
    for (const ing of ings) {
      if (ing.shopId <= 0) continue; // lab-crafted
      const have = stock[ing.shopId] || 0;
      if (have < ing.qty) missing[ing.shopId] = (missing[ing.shopId] || 0) + (ing.qty - have);
    }
  }
  const ids = Object.keys(missing).map(Number).sort((a, b) => a - b);
  if (ids.length === 0) return;

  const summary = [];
  for (const shopId of ids) {
    const need = missing[shopId];
    const mult = multiples[shopId] || 1;
    const purchases = Math.ceil(need / mult);
    let bought = 0;
    for (let i = 0; i < purchases; i++) {
      const r = await c.buy(shopId, 1);
      const data = r.data || {};
      if (data.coins != null) c._lastCoins = data.coins;
      if (r.result === "ok") bought += mult;
      else break;
    }
    if (bought > 0) summary.push("item " + shopId + " x" + bought);
  }
  if (summary.length) log.push("AUTOBUY: " + summary.join(", "));
}

// Open Chest debe ser una acción independiente: no debe ejecutar LOOP ni
// escanear/craftear el plan completo de la cuenta.
async function openChestAccount(acc, pem, log, saveAccountsFn) {
  normalizeAccountHistory(acc);
  const c = new MitosClient(acc.deviceId, pem);
  const sess = await c.loginIfNeeded(acc.sessionKey, acc.magic);
  if (sess && sess.sessionKey) {
    acc.sessionKey = sess.sessionKey;
    acc.magic = sess.magic;
  }
  const real = await c.fetchAccount();
  if (real.name) acc.name = real.name;
  if (real.coins != null) acc.coins = real.coins;
  const chest = await openDailyChest(c, acc.name || "?", log);
  if (chest.coins != null) acc.coins = chest.coins;
  if (saveAccountsFn) await saveAccountsFn();
  return chest;
}

// Detecta LOCALMENTE (0 peticiones al server) si la cuenta tiene trabajo
// pendiente. Usa endAt (timestamp absoluto del fin de cada craft) guardado en
// el ultimo scan: si endAt <= ahora, la pocion termino y hay que actuar.
function hasPendingWork(acc, plans) {
  const plan = acc.plan || "Unassigned";
  const planDef = (plans || []).find(p => p.name === plan);
  if (!planDef || !planDef.loop) return false;
  const planSlots = planDef.slots || [];
  const slots = Array.isArray(acc.slots) ? acc.slots : [];
  // lab vacio (0 slots reales): no hay trabajo. Solo se escanea si nunca se hizo.
  if (slots.length === 0) return !acc.slotsScannedAt;
  const now = Date.now();
  // edad del scan: si es viejo, el time restante ya se agoto
  const scannedAt = acc.slotsScannedAt ? Date.parse(acc.slotsScannedAt) : 0;
  const ageSec = (scannedAt > 0 && now > scannedAt) ? (now - scannedAt) / 1000 : 0;
  for (const s of slots) {
    const stt = String(s.craft || s.status || "");
    // pocion terminada segun endAt absoluto (no requiere re-scan)
    if (s.endAt > 0 && s.endAt <= now) return true;
    // pocion terminada: time restante real = time - edad del scan
    const realTime = Number(s.time) - ageSec;
    if (realTime <= 0 && s.name) return true;
    // slot ready con pocion (el server lo marco listo)
    if (stt === "ready" && s.name) return true;
    // slot libre (sin pocion, no locked) SOLO si el plan lo define: rellenar
    if (s.index >= 0 && stt !== "crafting" && !s.name && stt.toLowerCase() !== "locked" && planSlots[s.index]) return true;
  }
  return false;
}

async function runCycle(env, log) {
  const pem = await env.UTOPIA_KV.get(KV_KEYS.pem);
  if (!pem) { log.push("no pem en KV"); return; }
  const accounts = await kvGet(env, KV_KEYS.accounts, []);
  const plans = await kvGet(env, KV_KEYS.plans, []);
  if (accounts.length === 0) { log.push("sin cuentas en KV"); return; }
  accounts.forEach(normalizeAccountHistory);

  // El cursor rota entre cuentas; cada minuto avanza 1.
  const cursor = await kvGet(env, KV_KEYS.cursor, {});
  let idx = cursor.accountIdx || 0;
  if (idx >= accounts.length) idx = 0;
  const acc = accounts[idx];
  const saveAll = async () => { await kvSet(env, KV_KEYS.accounts, accounts); };
  const planMap = await readPlansMap(env);
  applyPlansMap(accounts, planMap);
  const plan = acc.plan || "Unassigned";
  const planDef = (plans || []).find(p => p.name === plan);
  try {
    // SOLO login/acciones cuando hay trabajo pendiente (pocion terminada por
    // endAt, slot libre, o nunca escaneado). El resto del tiempo: 0 peticiones.
    // Las pociones tardan 3.5h-18h, asi que el login real es muy esporadico.
    if (planDef && planDef.loop && hasPendingWork(acc, plans)) {
      await processAccount(acc, pem, plans, log, saveAll);
      log.push(`CICLO: cuenta ${idx + 1}/${accounts.length} (${acc.name || "?"}) -> trabajo hecho`);
    } else {
      log.push(`CICLO: cuenta ${idx + 1}/${accounts.length} (${acc.name || "?"}) -> sin trabajo, 0 requests`);
    }
  } catch (e) {
    log.push(`${acc.name || "?"}: ${String(e).slice(0, 100)}`);
  }
  await saveAll();
  idx = (idx + 1) % accounts.length;
  await env.UTOPIA_KV.put(KV_KEYS.cursor, JSON.stringify({
    last: new Date().toISOString(),
    accountIdx: idx,
    log: log.slice(-40),
  }));
}

// ============ DURABLE OBJECT: BOT 24/7 ============
// Vive en memoria con su storage (no snapshots viejos). El cron del minuto le
// hace ping; el DO decide si hay trabajo y programa alarmas exactas.
export class UtopiaBotDO extends DurableObject {
  constructor(state, env) {
    super(state, env);
    this.state = state;
    this.env = env;
    this.ctx = state.ctx;
    // estado local del DO (permanece en memoria entre invocaciones)
    this.nextAccountIdx = 0;
    this.cycleCount = 0;
    this.lastActivity = null;
  }

  async init() {
    const saved = await this.state.storage.get("meta");
    if (saved) {
      this.nextAccountIdx = saved.nextAccountIdx || 0;
      this.cycleCount = saved.cycleCount || 0;
    }
    return true;
  }

  // ping del cron cada minuto: procesa 1 cuenta si hay trabajo
  async ping() {
    await this.init();
    const pem = await this.env.UTOPIA_KV.get(KV_KEYS.pem);
    if (!pem) return { ok: false, error: "no pem" };
    const accounts = await kvGet(this.env, KV_KEYS.accounts, []);
    const plans = await kvGet(this.env, KV_KEYS.plans, []);
    if (accounts.length === 0) return { ok: false, error: "no accounts" };
    accounts.forEach(normalizeAccountHistory);

    const planMap = await readPlansMap(this.env);
    applyPlansMap(accounts, planMap);

    // buscar la primera cuenta que necesite accion:
    // 1) nunca escaneada -> scan completo (lab + slots + coins)
    // 2) con plan+loop y trabajo pendiente (pocion lista o slot libre)
    let worked = false;
    let workedName = "";
    const log = [];
    const processedDids = new Set();
    // guarda SIN pisar cambios externos: re-lee el KV y fusiona por deviceId.
    // Si el DO no proceso la cuenta en este ping, gana la version fresca del
    // KV (el scan manual del usuario es mas reciente que el snapshot del DO).
    const saveAll = async () => {
      const fresh = await kvGet(this.env, KV_KEYS.accounts, []);
      const mineById = new Map(accounts.map(a => [a.deviceId, a]));
      const out = fresh.map(f => {
        const mine = mineById.get(f.deviceId);
        if (!mine) return f;
        if (processedDids.has(f.deviceId)) return { ...f, ...mine };
        return { ...mine, ...f };
      });
      for (const a of accounts) {
        if (!fresh.some(f => f.deviceId === a.deviceId)) out.push(a);
      }
      await kvSet(this.env, KV_KEYS.accounts, out);
    };
    for (let k = 0; k < accounts.length; k++) {
      const idx = (this.nextAccountIdx + k) % accounts.length;
      const acc = accounts[idx];
      const plan = acc.plan || "Unassigned";
      const planDef = (plans || []).find(p => p.name === plan);

      // PRIMER SCAN: cuenta nunca escaneada -> login + lab completo + coins,
      // guarda slots/coins para que la app sepa su estado 24/7.
      if (!acc.slotsScannedAt) {
        try {
          const c = new MitosClient(acc.deviceId, pem);
          const sess = await c.loginIfNeeded(acc.sessionKey, acc.magic);
          if (sess && sess.sessionKey) { acc.sessionKey = sess.sessionKey; acc.magic = sess.magic; }
          const real = await c.fetchAccount();
          if (real.name) acc.name = real.name;
          if (real.coins != null) acc.coins = real.coins;
          const lab = await c.laboratory();
          const slots = (lab.data || {}).slots || [];
          updateLabSummary(acc, slots);
          processedDids.add(acc.deviceId);
          await saveAll();
          log.push(`${acc.name || "?"}: primer scan completo (${slots.length} slots, ${acc.coins} coins)`);
          worked = true;
          workedName = acc.name || "?";
          this.nextAccountIdx = (idx + 1) % accounts.length;
          break;
        } catch (e) {
          log.push(`${acc.name || "?"}: scan error: ${String(e).slice(0, 60)}`);
        }
        continue;
      }

      // con plan+loop: actuar SOLO si hay trabajo (pocion lista o slot libre)
      if (planDef && planDef.loop && hasPendingWork(acc, plans)) {
        try {
          processedDids.add(acc.deviceId);
          await processAccount(acc, pem, plans, log, saveAll);
          worked = true;
          workedName = acc.name || "?";
        } catch (e) {
          log.push(`${acc.name || "?"}: ${String(e).slice(0, 100)}`);
        }
        this.nextAccountIdx = (idx + 1) % accounts.length;
        break;
      }
    }
    // SOLO escribir accounts cuando el DO proceso algo (aunque falle): si no
    // hay trabajo, el KV no cambia y no hay que gastar writes (free tier 1,000/dia).
    if (processedDids.size > 0) await saveAll();
    this.cycleCount++;
    this.lastActivity = new Date().toISOString();
    await this.state.storage.put("meta", {
      nextAccountIdx: this.nextAccountIdx,
      cycleCount: this.cycleCount,
    });
    // guardar log en KV SOLO cuando hay novedades (trabajo hecho o scan):
    // el cron anterior escribia el cursor CADA minuto (2,880 writes/dia =
    // 2.8x el free tier de KV). Ahora: heartbeat cada 10 pings + al trabajar.
    this.pingCount = (this.pingCount || 0) + 1;
    const shouldWrite = worked || log.length > 0 || (this.pingCount % 10) === 0;
    if (shouldWrite) {
      const cursor = await kvGet(this.env, KV_KEYS.cursor, {});
      const newLog = [...(cursor.log || []), ...log];
      if (worked) newLog.push(`DO: ${workedName} -> trabajo hecho`);
      await this.env.UTOPIA_KV.put(KV_KEYS.cursor, JSON.stringify({
        last: new Date().toISOString(),
        accountIdx: this.nextAccountIdx,
        log: newLog.slice(-40),
      }));
    }
    return { ok: true, worked, workedName };
  }

  // forzar trabajo (CRAFT manual del panel)
  async craft(planName) {
    await this.init();
    const pem = await this.env.UTOPIA_KV.get(KV_KEYS.pem);
    const accounts = await kvGet(this.env, KV_KEYS.accounts, []);
    const plans = await kvGet(this.env, KV_KEYS.plans, []);
    if (!pem) return { ok: false, error: "no pem" };
    const planDef = plans.find(p => p.name === planName);
    if (!planDef) return { ok: false, error: "no plan" };
    const planMap = await readPlansMap(this.env);
    applyPlansMap(accounts, planMap);
    const targets = accounts.filter(a => a.plan === planName);
    // guarda SIN pisar cambios externos: re-lee el KV y fusiona por deviceId.
    // Solo la cuenta procesada por el DO gana; el resto conserva el KV fresco.
    const processedDids = new Set();
    const saveAll = async () => {
      const fresh = await kvGet(this.env, KV_KEYS.accounts, []);
      const mineById = new Map(accounts.map(a => [a.deviceId, a]));
      const out = fresh.map(f => {
        const mine = mineById.get(f.deviceId);
        if (!mine) return f;
        if (processedDids.has(f.deviceId)) return { ...f, ...mine };
        return { ...mine, ...f };
      });
      for (const a of accounts) {
        if (!fresh.some(f => f.deviceId === a.deviceId)) out.push(a);
      }
      await kvSet(this.env, KV_KEYS.accounts, out);
    };
    // el cursor del DO recuerda cual cuenta procesar; el panel llama hasta
    // completar todas. Una cuenta por llamada (límite de subrequests).
    const ciKey = "craftIdx_" + planName;
    let startIdx = (await this.state.storage.get(ciKey)) || 0;
    if (startIdx >= targets.length) startIdx = 0;
    const results = [];
    const log = [];
    const acc = targets[startIdx];
    if (acc) {
      try {
        processedDids.add(acc.deviceId);
        await processAccount(acc, pem, plans, log, saveAll);
        results.push({ name: acc.name || "?", ok: true, log });
      } catch (e) {
        results.push({ name: acc.name || "?", ok: false, error: String(e).slice(0, 60) });
      }
      const next = (startIdx + 1) % targets.length;
      await this.state.storage.put(ciKey, next);
      await saveAll();
      return { ok: true, total: targets.length, processed: results.length, done: next === 0, results };
    }
    await saveAll();
    return { ok: true, total: targets.length, processed: 0, done: true, results };
  }

  // endpoints internos del DO (llamados via stub.fetch desde el worker)
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/__ping") {
      return json(await this.ping());
    }
    if (url.pathname === "/__craft" && request.method === "POST") {
      const body = await request.json();
      return json(await this.craft(body.plan || ""));
    }
    return new Response("not found", { status: 404 });
  }
}

// ============ WORKER ============
export default {
  async scheduled(event, env, ctx) {
    try {
      const id = env.UTOPIA_BOT.idFromName("bot2");
      const stub = env.UTOPIA_BOT.get(id);
      await stub.fetch("https://do/__ping");
    } catch (e) {
      await env.UTOPIA_KV.put(KV_KEYS.cursor, JSON.stringify({ last: new Date().toISOString(), log: ["DO error: " + String(e).slice(0, 100)] }));
    }
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/state") {
      const accounts = await kvGet(env, KV_KEYS.accounts, []);
      const plans = await kvGet(env, KV_KEYS.plans, []);
      const cursor = await kvGet(env, KV_KEYS.cursor, {});
      let plansMap = await readPlansMap(env);
      // inicializar el map una sola vez con los planes existentes
      if (Object.keys(plansMap).length === 0 && accounts.length > 0) {
        plansMap = {};
        for (const a of accounts) if (a.plan) plansMap[a.deviceId] = a.plan;
        await env.UTOPIA_KV.put(KV_KEYS.plansMap, JSON.stringify(plansMap));
      }
      applyPlansMap(accounts, plansMap); // los planes del usuario ganan
      const before = JSON.stringify(accounts);
      accounts.forEach(normalizeAccountHistory);
      if (JSON.stringify(accounts) !== before) await kvSet(env, KV_KEYS.accounts, accounts);
      return json({ accounts, plans, last: cursor.last || null, log: cursor.log || [] });
    }

    if (url.pathname === "/api/cycle" && request.method === "GET") {
      const id = env.UTOPIA_BOT.idFromName("bot2");
      const stub = env.UTOPIA_BOT.get(id);
      // el DO recibe un fetch interno: /__ping y /__craft son sus endpoints
      ctx.waitUntil(stub.fetch("https://do/__ping").catch(() => {}));
      return json({ ok: true, started: true });
    }

    // CRAFT manual: craftea el plan activo en TODAS las cuentas asignadas
    // (recoge terminados + rellena libres + autobuy si el plan lo tiene)
    if (url.pathname === "/api/craft" && request.method === "POST") {
      const body = await request.json();
      const planName = body.plan || "";
      if (!planName) return json({ ok: false, error: "no plan" });
      const id = env.UTOPIA_BOT.idFromName("bot2");
      const stub = env.UTOPIA_BOT.get(id);
      const r = await stub.fetch("https://do/__craft", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan: planName }),
      });
      return json(await r.json());
    }

    if (url.pathname === "/api/setplan" && request.method === "POST") {
      const body = await request.json();
      const accounts = await kvGet(env, KV_KEYS.accounts, []);
      if (body.deviceId) {
        const plan = body.plan || "Unassigned";
        for (const a of accounts) {
          if (a.deviceId === body.deviceId) a.plan = plan;
        }
        await kvSet(env, KV_KEYS.accounts, accounts);
        // escribe en el mapa de planes SEPARADO: el cron no lo toca, asi el
        // cambio del usuario nunca se pisa por la eventual consistency del KV
        const plansMap = await readPlansMap(env);
        plansMap[body.deviceId] = plan;
        await env.UTOPIA_KV.put(KV_KEYS.plansMap, JSON.stringify(plansMap));
        return json({ ok: true });
      }
      // editar plan (slot o toggle): body = {index, slot?, potion?, key?, value?}
      const plans = await kvGet(env, KV_KEYS.plans, []);
      const p = plans[body.index];
      if (!p) return json({ ok: false, error: "no plan" });
      if (body.slot !== undefined) {
        const slots = p.slots || [];
        while (slots.length < 6) slots.push("");
        slots[body.slot] = body.potion || "";
        p.slots = slots;
      }
      if (body.key) p[body.key] = !!body.value;
      await kvSet(env, KV_KEYS.plans, plans);
      return json({ ok: true });
    }

    if (url.pathname === "/api/plan" && request.method === "POST") {
      const body = await request.json();
      const plans = await kvGet(env, KV_KEYS.plans, []);
      const accounts = await kvGet(env, KV_KEYS.accounts, []);
      const action = body.action || "";
      if (action === "create") {
        const name = String(body.name || "New Plan").trim().slice(0, 40);
        if (!name || plans.some(p => p.name === name)) return json({ ok: false, error: "invalid plan name" });
        plans.push({ name, slots: ["Superior Blink", "Mythical Speed Potion", "Speed Anticellular Shield", "Superior Portal Glue", "Super Glue Potion", "Legendary Speed Potion"], autobuy: false, loop: false });
      } else if (action === "rename") {
        const index = Number(body.index);
        const name = String(body.name || "").trim().slice(0, 40);
        if (!plans[index] || !name || plans.some((p, i) => i !== index && p.name === name)) return json({ ok: false, error: "invalid plan" });
        const oldName = plans[index].name;
        plans[index].name = name;
        for (const account of accounts) if (account.plan === oldName) account.plan = name;
        const plansMap = await readPlansMap(env);
        for (const key of Object.keys(plansMap)) {
          if (plansMap[key] === oldName) plansMap[key] = name;
        }
        await env.UTOPIA_KV.put(KV_KEYS.plansMap, JSON.stringify(plansMap));
      } else if (action === "delete") {
        const index = Number(body.index);
        if (plans.length <= 1 || !plans[index]) return json({ ok: false, error: "cannot delete plan" });
        const oldName = plans[index].name;
        plans.splice(index, 1);
        for (const account of accounts) if (account.plan === oldName) account.plan = "Unassigned";
        const plansMap = await readPlansMap(env);
        for (const key of Object.keys(plansMap)) {
          if (plansMap[key] === oldName) plansMap[key] = "Unassigned";
        }
        await env.UTOPIA_KV.put(KV_KEYS.plansMap, JSON.stringify(plansMap));
      } else {
        return json({ ok: false, error: "unknown action" });
      }
      await kvSet(env, KV_KEYS.plans, plans);
      await kvSet(env, KV_KEYS.accounts, accounts);
      return json({ ok: true, plans });
    }

    if (url.pathname === "/api/setmultiplier" && request.method === "POST") {
      const body = await request.json();
      const accounts = await kvGet(env, KV_KEYS.accounts, []);
      const mult = Math.max(1, Math.min(3, parseInt(body.multiplier) || 1));
      for (const a of accounts) {
        if (a.deviceId === body.deviceId) a.labMultiplier = mult;
      }
      await kvSet(env, KV_KEYS.accounts, accounts);
      return json({ ok: true });
    }

    // Escanea el laboratorio de UNA cuenta (para Account Labs) y actualiza coins
    if (url.pathname === "/api/lab" && request.method === "GET") {
      const deviceId = url.searchParams.get("did");
      if (!deviceId) return json({ ok: false, error: "no did" });
      const pem = await env.UTOPIA_KV.get(KV_KEYS.pem);
      const accounts = await kvGet(env, KV_KEYS.accounts, []);
      const acc = accounts.find(a => a.deviceId === deviceId);
      if (!acc || !pem) return json({ ok: false, error: "no acc" });
      try {
        const c = new MitosClient(deviceId, pem);
        const sess = await c.loginIfNeeded(acc.sessionKey, acc.magic);
        if (sess && sess.sessionKey) {
          acc.sessionKey = sess.sessionKey;
          acc.magic = sess.magic;
        }
        const real = await c.fetchAccount();
        if (real.name) { acc.name = real.name; }
        if (real.coins != null) { acc.coins = real.coins; }
        const lab = await c.laboratory();
        const slots = (lab.data || {}).slots || [];
        updateLabSummary(acc, slots);
        await kvSet(env, KV_KEYS.accounts, accounts);
        return json({ ok: true, name: acc.name, coins: acc.coins, slots, scannedAt: acc.slotsScannedAt });
      } catch (e) {
        return json({ ok: false, error: String(e).slice(0, 80) });
      }
    }

    // Compra un item en UNA cuenta (do=buy item=<id> packs=<n>)
    if (url.pathname === "/api/buy" && request.method === "POST") {
      const body = await request.json();
      const deviceId = body.deviceId;
      const itemId = parseInt(body.itemId) || 0;
      // max 40 packs/llamada: cada pack es 1 subrequest y el worker solo
      // permite 50 por invocacion (3 se reservan para login+fetch+guardado)
      const packs = Math.max(1, Math.min(40, parseInt(body.packs) || 1));
      if (!deviceId || !itemId) return json({ ok: false, error: "no did/item" });
      const pem = await env.UTOPIA_KV.get(KV_KEYS.pem);
      const accounts = await kvGet(env, KV_KEYS.accounts, []);
      const acc = accounts.find(a => a.deviceId === deviceId);
      if (!acc || !pem) return json({ ok: false, error: "no acc" });
      try {
        const c = new MitosClient(deviceId, pem);
        const sess = await c.loginIfNeeded(acc.sessionKey, acc.magic);
        if (sess && sess.sessionKey) {
          acc.sessionKey = sess.sessionKey;
          acc.magic = sess.magic;
        }
        const real = await c.fetchAccount();
        if (real.coins != null) acc.coins = real.coins;
        let r = null;
        let bought = 0;
        let error = "";
        // La API del juego compra un paquete por petición; igual que el PC,
        // repetimos la operación y detenemos la secuencia si falla un pack.
        for (let i = 0; i < packs; i++) {
          r = await c.buy(itemId, 1);
          const data = r.data || {};
          if (data.coins != null) acc.coins = data.coins;
          if (r.result !== "ok") {
            error = r.message || "buy failed on pack " + (i + 1);
            break;
          }
          bought++;
        }
        await kvSet(env, KV_KEYS.accounts, accounts);
        return json({ ok: bought > 0, result: r, name: acc.name, coins: acc.coins, bought, requestedPacks: packs, error });
      } catch (e) {
        return json({ ok: false, error: String(e).slice(0, 80) });
      }
    }

    // Abre UN cofre por invocacion; el panel repite hasta done:true.
    // El cursor vive en su propia key KV (el cron del DO no la pisa).
    if (url.pathname === "/api/openall" && request.method === "GET") {
      const pem = await env.UTOPIA_KV.get(KV_KEYS.pem);
      const accounts = await kvGet(env, KV_KEYS.accounts, []);
      if (!pem) return json({ ok: false, error: "no pem" });
      if (accounts.length === 0) return json({ ok: true, done: true, results: [] });
      const cursor = await kvGet(env, KV_KEYS.open, {});
      const start = cursor.openIdx || 0;
      const acc = accounts[start % accounts.length];
      const log = [];
      const saveAll = async () => { await kvSet(env, KV_KEYS.accounts, accounts); };
      const results = [];
      try {
        const chest = await openChestAccount(acc, pem, log, saveAll);
        results.push({ name: acc.name || "?", coins: acc.coins, ...chest, log });
      } catch (e) {
        results.push({ name: acc.name || "?", ok: false, rewards: [], error: String(e).slice(0, 80) });
      }
      await saveAll();
      const next = (start + 1) % accounts.length;
      await env.UTOPIA_KV.put(KV_KEYS.open, JSON.stringify({
        openIdx: next, lastOpen: new Date().toISOString(),
      }));
      return json({ ok: true, done: next === 0, results });
    }

    // panel: servir public/panel.html desde los assets
    if (url.pathname === "/" || url.pathname === "") {
      if (env.ASSETS) {
        const asset = await env.ASSETS.fetch(new Request("https://x/panel.html"));
        if (asset.status !== 404) {
          return new Response(await asset.text(), {
            headers: { "Content-Type": "text/html; charset=utf-8" },
          });
        }
      }
      return new Response("panel not found", { status: 500 });
    }
    // assets estaticos (sprites, panel.html)
    if (env.ASSETS) {
      const asset = await env.ASSETS.fetch(request);
      if (asset.status !== 404) return asset;
    }
    return new Response("not found", { status: 404 });
  },
};

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { "Content-Type": "application/json" },
  });
}


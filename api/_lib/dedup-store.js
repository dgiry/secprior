// api/lib/dedup-store.js — Persistance légère des IDs d'articles déjà envoyés
//
// Stockage : Vercel KV (Upstash Redis REST API) — gratuit sur Hobby plan.
// Setup    : Vercel Dashboard → Storage → Create KV → "Connect to project"
//            → injecte automatiquement KV_REST_API_URL + KV_REST_API_TOKEN
//
// Comportement si KV non configuré : fallback silencieux (Set vide, pas de sauvegarde).
// Le cron continue normalement sans déduplication inter-digest.

"use strict";

const SENT_KEY   = "digest:sent_ids";    // Set Redis des IDs d'articles déjà envoyés
const TOPICS_KEY = "digest:sent_topics"; // Set Redis des topicKeys déjà couverts
const SLOT_KEY   = "digest:last_sent_slot"; // String Redis du dernier créneau envoyé
const TTL_SEC    = 48 * 3600;            // TTL 48 h — couvre 2 cycles quotidiens
const SLOT_TTL   = 8  * 24 * 3600;      // TTL 8 j  — couvre une semaine hebdomadaire

/** Vérifie que les variables KV sont bien configurées. */
const _kvAvailable = () =>
  !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);

// ── Helpers REST Upstash ──────────────────────────────────────────────────────

/**
 * Exécute un appel REST simple vers Vercel KV (méthode GET pour les lectures).
 * Format : GET {url}/{command}/{key}
 */
async function _kvGet(command, key) {
  const url = `${process.env.KV_REST_API_URL}/${command}/${encodeURIComponent(key)}`;
  const res  = await fetch(url, {
    headers: { Authorization: `Bearer ${process.env.KV_REST_API_TOKEN}` },
    signal:  AbortSignal.timeout(5_000)
  });
  if (!res.ok) throw new Error(`KV ${command} HTTP ${res.status}`);
  return res.json();
}

/**
 * Exécute plusieurs commandes Redis en une seule requête HTTP (pipeline).
 * Chaque commande est un tableau : ["COMMAND", "arg1", "arg2", ...]
 */
async function _kvPipeline(commands) {
  const res = await fetch(`${process.env.KV_REST_API_URL}/pipeline`, {
    method:  "POST",
    headers: {
      Authorization:  `Bearer ${process.env.KV_REST_API_TOKEN}`,
      "Content-Type": "application/json"
    },
    body:   JSON.stringify(commands),
    signal: AbortSignal.timeout(5_000)
  });
  if (!res.ok) throw new Error(`KV pipeline HTTP ${res.status}`);
  return res.json();
}

// ── API publique ──────────────────────────────────────────────────────────────

/**
 * Charge les IDs des articles déjà envoyés lors des digest précédents.
 * Retourne un Set vide si KV non configuré ou en cas d'erreur (fallback propre).
 *
 * @returns {Promise<Set<string>>}
 */
async function loadSentIds() {
  if (!_kvAvailable()) {
    console.log("[dedup] KV non configuré — déduplication inter-digest désactivée");
    return new Set();
  }
  try {
    const json = await _kvGet("smembers", SENT_KEY);
    const ids  = Array.isArray(json.result) ? json.result : [];
    console.log("[dedup] %d IDs déjà envoyés chargés depuis KV", ids.length);
    return new Set(ids);
  } catch (e) {
    console.warn("[dedup] loadSentIds échoué (fallback Set vide) :", e.message);
    return new Set();
  }
}

/**
 * Persiste les IDs des articles envoyés dans ce digest (avec TTL 48 h).
 * SADD + EXPIRE envoyés en pipeline pour minimiser la latence.
 * Silencieux en cas d'erreur — ne bloque jamais le cron.
 *
 * @param {string[]} ids - IDs à marquer comme "déjà envoyés"
 */
async function saveSentIds(ids) {
  if (!_kvAvailable() || !ids.length) return;
  try {
    await _kvPipeline([
      ["sadd",   SENT_KEY, ...ids],   // ajoute au set existant
      ["expire", SENT_KEY, TTL_SEC]   // repart à 48 h à chaque envoi
    ]);
    console.log("[dedup] %d IDs persistés dans KV (TTL 48 h)", ids.length);
  } catch (e) {
    console.warn("[dedup] saveSentIds échoué (non bloquant) :", e.message);
  }
}

/**
 * Charge les topicKeys déjà couverts dans les digest précédents.
 * Retourne un Set vide si KV non configuré ou en cas d'erreur.
 *
 * @returns {Promise<Set<string>>}
 */
async function loadSentTopics() {
  if (!_kvAvailable()) return new Set();
  try {
    const json   = await _kvGet("smembers", TOPICS_KEY);
    const topics = Array.isArray(json.result) ? json.result : [];
    console.log("[dedup] %d topicKeys déjà couverts chargés depuis KV", topics.length);
    return new Set(topics);
  } catch (e) {
    console.warn("[dedup] loadSentTopics échoué (fallback Set vide) :", e.message);
    return new Set();
  }
}

/**
 * Persiste les topicKeys des sujets couverts dans ce digest (TTL 48 h).
 * Silencieux en cas d'erreur — ne bloque jamais le cron.
 *
 * @param {string[]} topicKeys
 */
async function saveSentTopics(topicKeys) {
  if (!_kvAvailable() || !topicKeys.length) return;
  try {
    await _kvPipeline([
      ["sadd",   TOPICS_KEY, ...topicKeys], // ajoute au set existant
      ["expire", TOPICS_KEY, TTL_SEC]       // repart à 48 h à chaque envoi
    ]);
    console.log("[dedup] %d topicKeys persistés dans KV (TTL 48 h)", topicKeys.length);
  } catch (e) {
    console.warn("[dedup] saveSentTopics échoué (non bloquant) :", e.message);
  }
}

/**
 * Charge le dernier créneau d'envoi ("YYYY-MM-DDTHH:MM" heure locale Montréal).
 * Retourne null si KV non configuré ou clé absente.
 *
 * @returns {Promise<string|null>}
 */
async function loadLastSlot() {
  if (!_kvAvailable()) return null;
  try {
    const json = await _kvGet("get", SLOT_KEY);
    return json.result || null;
  } catch (e) {
    console.warn("[dedup] loadLastSlot échoué :", e.message);
    return null;
  }
}

/**
 * Persiste le créneau d'envoi courant pour l'anti-doublon (TTL 8 j).
 * Silencieux en cas d'erreur — ne bloque jamais le cron.
 *
 * @param {string} slot - ex: "2026-03-25T08:30"
 */
async function saveLastSlot(slot) {
  if (!_kvAvailable() || !slot) return;
  try {
    await _kvPipeline([
      ["setex", SLOT_KEY, SLOT_TTL, slot] // SETEX key seconds value
    ]);
    console.log("[dedup] Créneau persisté : %s (TTL %dj)", slot, SLOT_TTL / 86400);
  } catch (e) {
    console.warn("[dedup] saveLastSlot échoué (non bloquant) :", e.message);
  }
}

// ── État du dernier run significatif ─────────────────────────────────────────

const RUN_KEY = "digest:last_run"; // JSON — état du dernier run réel (sent/failed/noArticles)
const RUN_TTL = 30 * 24 * 3600;   // TTL 30 j — garde l'historique un mois

/**
 * Persiste l'état du dernier run significatif en fusionnant avec l'état précédent.
 * La fusion préserve lastSentAt et lastFailureAt entre les runs : si le dernier run
 * est un échec, lastSentAt reste celle du précédent envoi réussi, et vice-versa.
 *
 * Silencieux en cas d'erreur — ne bloque jamais le cron.
 *
 * @param {{ lastResult, lastReason, lastStats, lastRunAt }} update
 */
async function saveLastRun(update) {
  if (!_kvAvailable()) return;
  try {
    // Charge l'état précédent pour préserver les timestamps de l'autre type de résultat
    let prev = {};
    try {
      const existing = await _kvGet("get", RUN_KEY);
      if (existing.result) prev = JSON.parse(existing.result);
    } catch (_) { /* ignore — on repart d'un état vide */ }

    const state = {
      // Timestamps préservés des runs précédents (non écrasés si non concernés)
      lastSentAt:    prev.lastSentAt    || null,
      lastSuccessAt: prev.lastSuccessAt || null,
      lastFailureAt: prev.lastFailureAt || null,
      // Écrase avec le résultat courant
      lastRunAt:  update.lastRunAt,
      lastResult: update.lastResult,   // "sent" | "failed" | "noArticles"
      lastReason: update.lastReason || null,
      lastStats:  update.lastStats,
      // Met à jour uniquement le timestamp correspondant au résultat
      ...(update.lastResult === "sent"   && { lastSentAt:    update.lastRunAt,
                                              lastSuccessAt: update.lastRunAt }),
      ...(update.lastResult === "failed" && { lastFailureAt: update.lastRunAt })
    };

    await _kvPipeline([
      ["setex", RUN_KEY, RUN_TTL, JSON.stringify(state)]
    ]);
    console.log("[dedup] lastRun persisté : %s (%s)", update.lastResult, update.lastRunAt);
  } catch (e) {
    console.warn("[dedup] saveLastRun échoué (non bloquant) :", e.message);
  }
}

/**
 * Charge l'état du dernier run depuis KV.
 * Retourne null si KV non configuré, clé absente ou erreur.
 *
 * @returns {Promise<object|null>}
 */
async function loadLastRun() {
  if (!_kvAvailable()) return null;
  try {
    const json = await _kvGet("get", RUN_KEY);
    return json.result ? JSON.parse(json.result) : null;
  } catch (e) {
    console.warn("[dedup] loadLastRun échoué :", e.message);
    return null;
  }
}

// ── Historique des derniers runs ──────────────────────────────────────────────

const HISTORY_KEY = "digest:run_history"; // JSON array des N derniers runs
const HISTORY_TTL = 30 * 24 * 3600;       // TTL 30 j
const HISTORY_MAX = 10;                    // on garde les 10 derniers runs

/**
 * Ajoute un run au début de l'historique et le persiste dans KV (TTL 30 j).
 * Conserve au maximum HISTORY_MAX entrées. Silencieux en cas d'erreur.
 *
 * @param {object} run — objet identique à ce que saveLastRun() reçoit
 */
async function saveRunHistory(run) {
  if (!_kvAvailable()) return;
  try {
    let history = [];
    try {
      const existing = await _kvGet("get", HISTORY_KEY);
      if (existing.result) history = JSON.parse(existing.result);
    } catch (_) { /* repart d'un tableau vide */ }

    history.unshift(run);
    if (history.length > HISTORY_MAX) history = history.slice(0, HISTORY_MAX);

    await _kvPipeline([
      ["setex", HISTORY_KEY, HISTORY_TTL, JSON.stringify(history)]
    ]);
    console.log("[dedup] runHistory persisté (%d entrées)", history.length);
  } catch (e) {
    console.warn("[dedup] saveRunHistory échoué (non bloquant) :", e.message);
  }
}

/**
 * Charge l'historique des derniers runs depuis KV.
 * Retourne un tableau vide si KV non configuré ou en cas d'erreur.
 *
 * @returns {Promise<object[]>}
 */
async function loadRunHistory() {
  if (!_kvAvailable()) return [];
  try {
    const json = await _kvGet("get", HISTORY_KEY);
    return json.result ? JSON.parse(json.result) : [];
  } catch (e) {
    console.warn("[dedup] loadRunHistory échoué :", e.message);
    return [];
  }
}

// ── Historique des briefings envoyés ─────────────────────────────────────────

const BRIEFING_HIST_KEY = "digest:briefing_history"; // JSON array des N derniers briefings
const BRIEFING_HIST_TTL = 60 * 24 * 3600;            // TTL 60 j
const BRIEFING_HIST_MAX = 10;                         // 10 derniers briefings envoyés

/**
 * Persiste un briefing envoyé dans l'historique (TTL 60 j, max 10 entrées).
 * Silencieux en cas d'erreur — ne bloque jamais le cron.
 *
 * @param {{ sentAt, slot, subject, topCount, topArticles }} entry
 *   topArticles : tableau de { rank, title, topicKey, criticality, isKEV,
 *                              cveId, epssScore, cvssScore, link }
 */
async function saveBriefingHistory(entry) {
  if (!_kvAvailable()) return;
  try {
    let history = [];
    try {
      const existing = await _kvGet("get", BRIEFING_HIST_KEY);
      if (existing.result) history = JSON.parse(existing.result);
    } catch (_) { /* repart d'un tableau vide */ }

    history.unshift(entry);
    if (history.length > BRIEFING_HIST_MAX) history = history.slice(0, BRIEFING_HIST_MAX);

    await _kvPipeline([
      ["setex", BRIEFING_HIST_KEY, BRIEFING_HIST_TTL, JSON.stringify(history)]
    ]);
    console.log("[dedup] briefingHistory persisté (%d entrées)", history.length);
  } catch (e) {
    console.warn("[dedup] saveBriefingHistory échoué (non bloquant) :", e.message);
  }
}

/**
 * Charge l'historique des briefings envoyés depuis KV.
 * Retourne un tableau vide si KV non configuré ou en cas d'erreur.
 *
 * @returns {Promise<object[]>}
 */
async function loadBriefingHistory() {
  if (!_kvAvailable()) return [];
  try {
    const json = await _kvGet("get", BRIEFING_HIST_KEY);
    return json.result ? JSON.parse(json.result) : [];
  } catch (e) {
    console.warn("[dedup] loadBriefingHistory échoué :", e.message);
    return [];
  }
}

module.exports = {
  loadSentIds, saveSentIds,
  loadSentTopics, saveSentTopics,
  loadLastSlot, saveLastSlot,
  saveLastRun, loadLastRun,
  saveRunHistory, loadRunHistory,
  saveBriefingHistory, loadBriefingHistory
};

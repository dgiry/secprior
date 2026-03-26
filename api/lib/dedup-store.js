// api/lib/dedup-store.js — Persistance légère des IDs d'articles déjà envoyés
//
// Stockage : Vercel KV (Upstash Redis REST API) — gratuit sur Hobby plan.
// Setup    : Vercel Dashboard → Storage → Create KV → "Connect to project"
//            → injecte automatiquement KV_REST_API_URL + KV_REST_API_TOKEN
//
// Comportement si KV non configuré : fallback silencieux (Set vide, pas de sauvegarde).
// Le cron continue normalement sans déduplication inter-digest.

"use strict";

const SENT_KEY = "digest:sent_ids"; // Clé Redis du set d'IDs déjà envoyés
const TTL_SEC  = 48 * 3600;         // TTL 48 h — couvre 2 cycles quotidiens

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

module.exports = { loadSentIds, saveSentIds };

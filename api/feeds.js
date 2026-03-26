// api/feeds.js — Endpoint public retournant la liste canonique des flux RSS
//
// Utilisé par le front (js/app.js → _loadFeedsFromAPI) pour charger les feeds
// depuis la source unique (api/lib/feeds.js) plutôt que depuis config.js.
//
// GET /api/feeds
// → { feeds: [...], count: 13 }
//
// Accès public, sans authentification — les URLs sont des flux publics.
// Cache CDN Vercel 1 h pour éviter les appels inutiles.

"use strict";

const { FEEDS } = require("./lib/feeds");

module.exports = async (req, res) => {
  // Cache 1 h côté CDN + client (les feeds changent rarement)
  res.setHeader("Cache-Control", "public, max-age=3600, stale-while-revalidate=600");
  res.setHeader("Content-Type", "application/json");

  return res.status(200).json({
    feeds: FEEDS,
    count: FEEDS.length
  });
};

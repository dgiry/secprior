// service-worker.js — CyberVeille Pro PWA
// Stratégie :
//   • Fichiers statiques (HTML/CSS/JS/SVG) → Stale-While-Revalidate
//     (sert le cache immédiatement, met à jour en arrière-plan)
//   • Appels API / RSS externes → Network-First avec fallback cache
//     (essaie le réseau, replie sur le cache si hors-ligne)

const SW_VERSION   = 'v29';
const CACHE_STATIC = `cvpro-static-${SW_VERSION}`;
const CACHE_DATA   = `cvpro-data-${SW_VERSION}`;

// Fichiers pré-cachés à l'installation (app shell)
const APP_SHELL = [
  '/',
  '/index.html',
  '/manifest.json',
  '/css/style.css',
  '/js/config.js',
  '/js/stats.js',
  '/js/demo-data.js',
  '/js/feed-manager.js',
  '/js/scorer.js',
  '/js/storage.js',
  '/js/feeds.js',
  '/js/enricher.js',
  '/js/deduplicator.js',
  '/js/contextualizer.js',
  '/js/ioc-extractor.js',
  '/js/pipeline.js',
  '/js/nvd.js',
  '/js/email-alerts.js',
  '/js/risk-filter.js',
  '/js/settings-modal.js',
  '/js/watchlist-modal.js',
  '/js/article-modal.js',
  '/js/ui.js',
  '/js/pdf-report.js',
  '/js/briefing-panel.js',
  '/js/health-panel.js',
  '/js/vendor-panel.js',
  '/js/pwa.js',
  '/js/app.js',
  '/icons/icon.svg'
];

// ── Install : pré-cache de l'app shell ───────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_STATIC)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
      .catch(err => console.warn('[SW] Pré-cache partiel:', err))
  );
});

// ── Activate : suppression des anciens caches ─────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(k => k !== CACHE_STATIC && k !== CACHE_DATA)
          .map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ── Fetch : routage des requêtes ──────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignorer les non-GET et les schémas non-HTTP
  if (request.method !== 'GET') return;
  if (!url.protocol.startsWith('http')) return;

  // Ignorer les DevTools / extensions
  if (url.hostname === 'localhost' && url.port && url.port !== location.port) return;

  // ── Requêtes same-origin (HTML, CSS, JS, assets) → Stale-While-Revalidate
  if (url.origin === self.location.origin) {
    event.respondWith(staleWhileRevalidate(request, CACHE_STATIC));
    return;
  }

  // ── Requêtes externes (RSS, NVD, EPSS, KEV, allorigins) → Network-First
  event.respondWith(networkFirst(request, CACHE_DATA));
});

// ── Message : mise à jour forcée ──────────────────────────────────────────────
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ── Stale-While-Revalidate ────────────────────────────────────────────────────
// Sert immédiatement depuis le cache, met à jour en arrière-plan
async function staleWhileRevalidate(request, cacheName) {
  const cache    = await caches.open(cacheName);
  const cached   = await cache.match(request, { ignoreSearch: true });

  // Revalider en arrière-plan (ne bloque pas la réponse)
  const fetchPromise = fetch(request).then(response => {
    if (response.ok) {
      cache.put(request, response.clone());
    }
    return response;
  }).catch(() => null);

  // Retourner le cache immédiatement ou attendre le réseau
  return cached || fetchPromise || offlineFallback(request);
}

// ── Network-First ─────────────────────────────────────────────────────────────
// Essaie le réseau d'abord, cache en fallback si hors-ligne
async function networkFirst(request, cacheName) {
  const cache = await caches.open(cacheName);
  try {
    const response = await fetch(request);
    if (response.ok) {
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cached = await cache.match(request, { ignoreSearch: true });
    if (cached) return cached;
    // Fallback JSON vide pour les API
    return new Response(
      JSON.stringify({ error: 'offline', cached: false }),
      { status: 503, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

// ── Fallback hors-ligne ────────────────────────────────────────────────────────
async function offlineFallback(request) {
  const cache = await caches.open(CACHE_STATIC);
  // Pour les pages HTML : servir index.html
  if (request.destination === 'document') {
    return cache.match('/index.html') || new Response('Hors-ligne', { status: 503 });
  }
  return new Response('Hors-ligne', { status: 503 });
}

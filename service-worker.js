// service-worker.js — CyberVeille Pro PWA
//
// Stratégie à deux vitesses :
//
//   DEV / PREVIEW (localhost / 127.0.0.1)
//   ─────────────────────────────────────
//   • Tout same-origin → Network-First
//     (les assets versionnés ?v=N arrivent toujours frais du serveur)
//
//   PRODUCTION (domaine public)
//   ───────────────────────────
//   • Assets versionnés (?v=N) → Network-First + mise en cache
//     (le cache-busting est respecté : ?v=14 ≠ ?v=13)
//   • Fichiers structurels sans version (/, index.html, manifest) → Stale-While-Revalidate
//     (chargement rapide + mise à jour en arrière-plan + offline)
//   • Requêtes externes (RSS, NVD, EPSS, KEV) → Network-First + fallback cache offline
//
// Correctifs appliqués :
//   ✓ Suppression de ignoreSearch:true dans staleWhileRevalidate
//     (chaque ?v=N est désormais une entrée de cache distincte)
//   ✓ APP_SHELL réduit aux fichiers structurels (sans JS/CSS versionnés)
//     (les JS/CSS sont fetched Network-First au premier usage, pas pré-cachés)
//   ✓ Détection localhost → Network-First automatique en dev

const SW_VERSION   = 'v65';
const CACHE_STATIC = `cvpro-static-${SW_VERSION}`;
const CACHE_DATA   = `cvpro-data-${SW_VERSION}`;

// Dev/preview : Network-First pour tout (previews et reloads toujours frais)
const IS_DEV = ['localhost', '127.0.0.1'].includes(self.location.hostname);

// App shell réduit : uniquement les fichiers structurels non versionnés.
// Les JS/CSS (chargés avec ?v=N dans index.html) passent Network-First — inutile de les pré-cacher.
const APP_SHELL = [
  '/',
  '/index.html',
  '/manifest.json',
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

  // Ignorer les DevTools / extensions (ports différents sur localhost)
  if (url.hostname === 'localhost' && url.port && url.port !== location.port) return;

  // ── Requêtes same-origin (HTML, CSS, JS, assets) ─────────────────────────
  if (url.origin === self.location.origin) {
    const hasVersion = url.searchParams.has('v');
    const isDocument = request.destination === 'document';

    // Network-First si :
    //   • dev/preview (localhost) → toujours frais
    //   • asset versionné (?v=N) → cache-busting respecté
    //   • navigation HTML (index.html) → jamais de version fantôme après mise à jour SW
    if (IS_DEV || hasVersion || isDocument) {
      event.respondWith(networkFirstStatic(request));
      return;
    }

    // Prod + fichier statique sans version (manifest.json, icon.svg…) → SWR
    event.respondWith(staleWhileRevalidate(request, CACHE_STATIC));
    return;
  }

  // ── Requêtes externes (RSS, NVD, EPSS, KEV, allorigins) → Network-First ──
  event.respondWith(networkFirst(request, CACHE_DATA));
});

// ── Message : mise à jour forcée ──────────────────────────────────────────────
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ── Network-First (assets same-origin versionnés ou dev) ─────────────────────
// Toujours essaye le réseau ; met en cache en cas de succès.
// En cas d'échec réseau, replie sur le cache (exact match — pas d'ignoreSearch).
async function networkFirstStatic(request) {
  const cache = await caches.open(CACHE_STATIC);
  try {
    const response = await fetch(request);
    if (response.ok) cache.put(request, response.clone());
    return response;
  } catch {
    const cached = await cache.match(request);
    if (cached) return cached;
    return offlineFallback(request);
  }
}

// ── Stale-While-Revalidate (fichiers structurels sans version en prod) ────────
// Sert immédiatement depuis le cache, met à jour en arrière-plan.
// NOTE : pas d'ignoreSearch → chaque URL est une entrée distincte.
async function staleWhileRevalidate(request, cacheName) {
  const cache  = await caches.open(cacheName);
  const cached = await cache.match(request); // exact match — ignoreSearch supprimé

  // Revalider en arrière-plan (ne bloque pas la réponse)
  const fetchPromise = fetch(request).then(response => {
    if (response.ok) cache.put(request, response.clone());
    return response;
  }).catch(() => null);

  // Retourner le cache immédiatement ou attendre le réseau
  return cached || fetchPromise || offlineFallback(request);
}

// ── Network-First (requêtes externes RSS / API) ───────────────────────────────
// Essaie le réseau d'abord, cache en fallback si hors-ligne.
// ignoreSearch conservé ici : les API externes peuvent varier leurs params.
async function networkFirst(request, cacheName) {
  const cache = await caches.open(cacheName);
  try {
    const response = await fetch(request);
    if (response.ok) cache.put(request, response.clone());
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
  if (request.destination === 'document') {
    return cache.match('/index.html') || new Response('Hors-ligne', { status: 503 });
  }
  return new Response('Hors-ligne', { status: 503 });
}

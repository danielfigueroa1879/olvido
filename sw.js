/*
 * sw.js — Service Worker de Bóveda Olvido.
 *
 * Objetivo: que la app se pueda instalar y abrir sin conexión (offline).
 * Estrategia: "network-first" para los archivos propios (siempre intenta la
 * versión más nueva; si no hay red, usa la copia en caché). Las llamadas a
 * Supabase y al CDN NO se interceptan (van directo a la red).
 *
 * Nota: aquí NO se guarda nada sensible. La bóveda cifrada vive en localStorage
 * (gestionada por la app), no en esta caché.
 */

const CACHE = "boveda-olvido-v1";

// Archivos del "cascarón" de la app para precargar.
const SHELL = [
  "./",
  "./index.html",
  "./styles.css",
  "./config.js",
  "./crypto.js",
  "./supabase.js",
  "./app.js",
  "./manifest.webmanifest",
  "./favicon/favicon.svg",
  "./favicon/favicon-96x96.png",
  "./favicon/apple-touch-icon.png",
  "./favicon/web-app-manifest-192x192.png",
  "./favicon/web-app-manifest-512x512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(SHELL))
      .then(() => self.skipWaiting())
      .catch(() => {})
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  // Solo gestionamos archivos de nuestro propio origen (no Supabase ni CDNs).
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    fetch(req)
      .then((res) => {
        // Guarda una copia fresca en caché para uso offline.
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        return res;
      })
      .catch(async () => {
        // Sin red: sirve desde caché; si es una navegación, cae al index.
        const cached = await caches.match(req);
        return cached || caches.match("./index.html");
      })
  );
});

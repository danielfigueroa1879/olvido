/*
 * app.js — Orquestación de la UI, cuenta en la nube y estado en memoria.
 *
 * Modelo: cada usuario tiene UNA bóveda en la nube (Supabase). Se accede con
 * correo + contraseña maestra desde cualquier dispositivo. La bóveda se cifra
 * en el dispositivo (AES-256-GCM); el servidor solo guarda el texto cifrado.
 *
 * Estado sensible (llave de cifrado, entradas descifradas) vive SOLO en memoria
 * mientras la bóveda está abierta. Al bloquear o cerrar sesión se limpia.
 * En localStorage se guarda una copia CIFRADA como respaldo/caché offline.
 */

(() => {
  "use strict";

  const LS = {
    LAST_EMAIL: "baul.last_email",   // último correo usado (para prellenar)
    SETTINGS: "baul.settings",       // ajustes locales (auto-bloqueo)
    CACHE_PREFIX: "baul.cache.",      // caché cifrada por correo
  };

  // ---- Estado en memoria (se borra al bloquear / cerrar sesión) ----
  let encKey = null;         // CryptoKey AES-GCM derivada de la contraseña maestra
  let email = "";            // correo de la sesión
  let entries = [];          // [{ id, title, url, username, password, notes, updatedAt, deleted? }]
  let settings = { autolockMin: 5 };
  let autolockTimer = null;
  let mode = "signin";       // "signin" | "signup" | "unlock"

  // ---- Helpers DOM ----
  const $ = (sel) => document.querySelector(sel);
  function show(el) { el.hidden = false; }
  function hide(el) { el.hidden = true; }

  function toast(msg, kind = "") {
    const t = $("#toast");
    t.textContent = msg;
    t.className = "toast " + kind;
    t.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => (t.hidden = true), 3000);
  }

  function cacheKey() { return LS.CACHE_PREFIX + (email || "").trim().toLowerCase(); }

  // =====================================================================
  // ARRANQUE
  // =====================================================================
  async function init() {
    loadSettings();
    wireGlobalEvents();
    wireAuthEvents();

    if (!Cloud.configured()) {
      show($("#setup-warn"));
      $("#auth-btn").disabled = true;
      return;
    }

    // ¿Hay una sesión recordada? Entonces solo pedimos la contraseña maestra.
    const session = await Cloud.getSession();
    if (session && session.user && session.user.email) {
      email = session.user.email;
      setMode("unlock");
    } else {
      const last = localStorage.getItem(LS.LAST_EMAIL) || "";
      $("#auth-email").value = last;
      setMode("signin");
    }
  }

  function loadSettings() {
    try {
      const s = JSON.parse(localStorage.getItem(LS.SETTINGS) || "{}");
      settings = { ...settings, ...s };
    } catch {}
  }

  // =====================================================================
  // PANTALLA DE ACCESO
  // =====================================================================
  function setMode(next) {
    mode = next;
    const subtitle = $("#auth-subtitle");
    const emailField = $("#auth-email");
    const confirmField = $("#confirm-field");
    const strength = $("#strength");
    const newWarn = $("#new-account-warn");
    const btn = $("#auth-btn");
    const switchText = $("#switch-text");
    const switchBtn = $("#switch-mode");
    const reunlock = $("#reunlock-line");

    hide($("#auth-error"));
    hide($("#auth-info"));

    if (mode === "signup") {
      subtitle.textContent = "Crea tu cuenta";
      btn.textContent = "Crear cuenta";
      emailField.disabled = false;
      show(confirmField); show(strength); show(newWarn);
      switchText.textContent = "¿Ya tienes cuenta?";
      switchBtn.textContent = "Inicia sesión";
      hide(reunlock);
    } else if (mode === "unlock") {
      subtitle.textContent = "Desbloquea tu bóveda";
      btn.textContent = "Desbloquear";
      $("#auth-email").value = email;
      emailField.disabled = true;
      hide(confirmField); hide(strength); hide(newWarn);
      switchText.textContent = "";
      switchBtn.textContent = "";
      switchBtn.hidden = true;
      show(reunlock);
      $("#auth-password").focus();
    } else { // signin
      subtitle.textContent = "Inicia sesión para abrir tu bóveda";
      btn.textContent = "Entrar";
      emailField.disabled = false;
      hide(confirmField); hide(strength); hide(newWarn);
      switchText.textContent = "¿No tienes cuenta?";
      switchBtn.textContent = "Crear una";
      switchBtn.hidden = false;
      hide(reunlock);
    }
  }

  function wireAuthEvents() {
    const pwInput = $("#auth-password");
    pwInput.addEventListener("input", () => {
      if ($("#confirm-field").hidden) return;
      const { score, label } = Vault.estimateStrength(pwInput.value);
      $("#strength-fill").style.width = (score * 25) + "%";
      $("#strength-fill").dataset.score = score;
      $("#strength-label").textContent = label;
    });

    $("#switch-mode").addEventListener("click", () => {
      setMode(mode === "signup" ? "signin" : "signup");
    });

    $("#use-other").addEventListener("click", async () => {
      await Cloud.signOut();
      email = "";
      $("#auth-email").value = localStorage.getItem(LS.LAST_EMAIL) || "";
      $("#auth-password").value = "";
      setMode("signin");
    });

    $("#auth-form").addEventListener("submit", onAuthSubmit);
  }

  function authError(msg) {
    const e = $("#auth-error");
    e.textContent = msg;
    show(e);
    hide($("#auth-info"));
  }
  function authInfo(msg) {
    const e = $("#auth-info");
    e.textContent = msg;
    show(e);
    hide($("#auth-error"));
  }
  function authBusy(b) {
    const btn = $("#auth-btn");
    btn.disabled = b;
    btn.dataset.label = btn.dataset.label || btn.textContent;
    btn.textContent = b ? "…" : btn.dataset.label;
    if (!b) btn.dataset.label = "";
  }

  async function onAuthSubmit(e) {
    e.preventDefault();
    hide($("#auth-error"));
    hide($("#auth-info"));

    const emailVal = (mode === "unlock" ? email : $("#auth-email").value).trim();
    const pw = $("#auth-password").value;

    if (!emailVal) return authError("Escribe tu correo.");
    if (!pw) return authError("Escribe tu contraseña.");
    if (mode === "signup") {
      const confirm = $("#auth-password-confirm").value;
      if (pw.length < 8) return authError("Usa al menos 8 caracteres (mejor una frase larga).");
      if (pw !== confirm) return authError("Las contraseñas no coinciden.");
    }

    authBusy(true);
    try {
      // Derivamos ambas llaves desde (correo, contraseña). Determinista.
      const { encKey: k, authPassword } = await Vault.deriveKeys(pw, emailVal);

      if (mode === "signup") {
        await Cloud.signUp(emailVal, authPassword);
        // Si la confirmación de correo está desactivada, ya hay sesión; si no, avisamos.
        try {
          await Cloud.signIn(emailVal, authPassword);
        } catch (signInErr) {
          authInfo("Cuenta creada. Revisa tu correo para confirmarla y luego inicia sesión.");
          setMode("signin");
          return;
        }
        encKey = k; email = emailVal;
        entries = [];
        await pushVault(); // crea la fila cifrada vacía en la nube
        localStorage.setItem(LS.LAST_EMAIL, email);
        openMain();
        return;
      }

      if (mode === "signin") {
        await Cloud.signIn(emailVal, authPassword);
      }
      // signin y unlock comparten el resto: ya hay sesión válida.
      encKey = k; email = emailVal;

      const remote = await Cloud.loadVault();
      if (!remote || !remote.content) {
        // Cuenta sin bóveda todavía (raro): la creamos vacía.
        entries = [];
        await pushVault();
      } else {
        const file = JSON.parse(remote.content);
        const data = await Vault.decryptWithKey(encKey, file);
        entries = Array.isArray(data.entries) ? data.entries : [];
        localStorage.setItem(cacheKey(), remote.content);
      }
      localStorage.setItem(LS.LAST_EMAIL, email);
      openMain();
    } catch (err) {
      authError(err.message || "No se pudo acceder.");
    } finally {
      authBusy(false);
    }
  }

  // =====================================================================
  // BLOQUEO / DESBLOQUEO / CIERRE DE SESIÓN
  // =====================================================================
  function openMain() {
    $("#auth-password").value = "";
    const c = $("#auth-password-confirm"); if (c) c.value = "";
    hide($("#auth-screen"));
    show($("#main-screen"));
    $("#account-email").textContent = email;
    $("#autolock-min").value = settings.autolockMin || 5;
    render();
    resetAutolock();
    // Baja cambios remotos y fusiona (por si otro dispositivo agregó algo).
    syncPull(true);
  }

  function lock() {
    // Limpia lo sensible de memoria y del DOM (mantiene la sesión de la nube).
    encKey = null;
    entries = [];
    clearTimeout(autolockTimer);
    $("#entries").innerHTML = "";
    $("#search").value = "";
    hide($("#main-screen"));
    show($("#auth-screen"));
    setMode("unlock");
  }

  async function signOutFull() {
    clearTimeout(autolockTimer);
    encKey = null;
    entries = [];
    await Cloud.signOut();
    $("#entries").innerHTML = "";
    $("#search").value = "";
    $("#settings-dialog").close();
    hide($("#main-screen"));
    show($("#auth-screen"));
    $("#auth-password").value = "";
    $("#auth-email").value = localStorage.getItem(LS.LAST_EMAIL) || "";
    email = "";
    setMode("signin");
  }

  function resetAutolock() {
    clearTimeout(autolockTimer);
    const min = Math.max(1, Number(settings.autolockMin) || 5);
    autolockTimer = setTimeout(lock, min * 60 * 1000);
  }

  // =====================================================================
  // FUSIÓN + PERSISTENCIA (cifrar, guardar local y subir)
  // =====================================================================
  /**
   * Fusiona dos listas de entradas SIN perder datos.
   * Por cada id gana la versión con updatedAt más reciente. Los tombstones
   * (deleted) participan igual, para que una eliminación no reviva al fusionar.
   */
  function mergeEntries(a, b) {
    const map = new Map();
    for (const en of [...(a || []), ...(b || [])]) {
      if (!en || !en.id) continue;
      const prev = map.get(en.id);
      if (!prev || (en.updatedAt || "") >= (prev.updatedAt || "")) map.set(en.id, en);
    }
    return [...map.values()];
  }

  /** Cifra el estado actual y lo guarda en caché local. */
  function encryptCurrent() {
    return Vault.encryptWithKey(encKey, { entries });
  }

  /** Guarda local + sube a la nube (fusionando antes con lo remoto). */
  async function pushVault() {
    if (!encKey) return;
    // Fusiona con lo remoto para no pisar cambios de otro dispositivo.
    try {
      const remote = await Cloud.loadVault();
      if (remote && remote.content) {
        const rf = JSON.parse(remote.content);
        const rd = await Vault.decryptWithKey(encKey, rf);
        entries = mergeEntries(entries, Array.isArray(rd.entries) ? rd.entries : []);
      }
    } catch { /* si falla la lectura remota, seguimos con lo local */ }

    const file = await encryptCurrent();
    const content = JSON.stringify(file);
    try { localStorage.setItem(cacheKey(), content); } catch {}

    try {
      await Cloud.saveVault(content);
      syncMsg("Guardado en la nube ✓", "ok");
    } catch (err) {
      syncMsg("Guardado local. " + err.message, "err");
    }
  }

  async function syncPull(silent = false) {
    if (!encKey) return;
    try {
      if (!silent) syncMsg("Sincronizando…");
      const remote = await Cloud.loadVault();
      if (!remote || !remote.content) { if (!silent) syncMsg("Bóveda al día ✓", "ok"); return; }
      const file = JSON.parse(remote.content);
      const data = await Vault.decryptWithKey(encKey, file);
      const remoteEntries = Array.isArray(data.entries) ? data.entries : [];
      entries = mergeEntries(entries, remoteEntries);
      try { localStorage.setItem(cacheKey(), JSON.stringify(await encryptCurrent())); } catch {}
      render($("#search").value);
      if (!silent) syncMsg("Sincronizado ✓", "ok");
    } catch (err) {
      if (!silent) syncMsg("No se pudo sincronizar: " + err.message, "err");
    }
  }

  async function syncNow() {
    if (!encKey) return;
    await syncPull(false);
    await pushVault();
  }

  function syncMsg(msg, kind = "") {
    const el = $("#sync-status");
    el.textContent = msg;
    el.className = "sync-status " + kind;
    el.hidden = false;
    if (kind === "ok") setTimeout(() => (el.hidden = true), 2500);
  }

  // =====================================================================
  // RENDER DE ENTRADAS
  // =====================================================================
  function render(filter = "") {
    const list = $("#entries");
    list.innerHTML = "";
    const q = filter.trim().toLowerCase();
    const active = entries.filter((en) => en && !en.deleted);
    const items = active
      .filter((en) =>
        !q ||
        (en.title || "").toLowerCase().includes(q) ||
        (en.username || "").toLowerCase().includes(q) ||
        (en.url || "").toLowerCase().includes(q))
      .sort((a, b) => (a.title || "").localeCompare(b.title || ""));

    $("#empty-state").hidden = active.length !== 0;

    let n = 0;
    for (const en of items) {
      n++;
      const card = document.createElement("article");
      card.className = "entry";
      const href = safeUrl(en.url);
      const title = en.title || "(sin título)";
      const ini = initial(title);
      const color = avatarColor(title);
      card.innerHTML = `
        <span class="entry-num">${n}</span>
        <div class="entry-avatar" style="background:${color}">${escapeHtml(ini)}</div>
        <button type="button" class="entry-open" data-act="open">
          <div class="entry-title">${escapeHtml(title)}</div>
          ${en.username ? `<div class="entry-sub">${escapeHtml(en.username)}</div>` : ""}
          ${href ? `<span class="entry-url">${escapeHtml(en.url)}</span>` : ""}
        </button>
        <div class="entry-actions">
          <button type="button" class="ghost entry-key" data-act="copy-pass" title="Copiar contraseña">🔑</button>
          <button type="button" class="entry-chevron" data-act="open" title="Ver / editar" aria-label="Abrir">›</button>
        </div>`;
      card.querySelector('.entry-open').onclick = () => openEntryDialog(en);
      card.querySelector('.entry-chevron').onclick = () => openEntryDialog(en);
      card.querySelector('[data-act="copy-pass"]').onclick = (e) => { e.stopPropagation(); copyClip(en.password, "Contraseña copiada (se borra en 20s)", true); };
      list.appendChild(card);
    }
  }

  // Inicial (primera letra útil) del título para el avatar.
  function initial(s) {
    const m = String(s || "").trim().match(/[a-zA-Z0-9ñÑáéíóúÁÉÍÓÚ]/);
    return m ? m[0].toUpperCase() : "•";
  }
  // Color estable a partir del texto (para el avatar redondo).
  function avatarColor(s) {
    let h = 0;
    const str = String(s || "");
    for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) % 360;
    return `hsl(${h}, 55%, 45%)`;
  }

  // =====================================================================
  // MODAL DE ENTRADA
  // =====================================================================
  function openEntryDialog(entry = null) {
    const dlg = $("#entry-dialog");
    $("#entry-dialog-title").textContent = entry ? "Editar entrada" : "Nueva entrada";
    $("#entry-id").value = entry?.id || "";
    $("#entry-title").value = entry?.title || "";
    $("#entry-url").value = entry?.url || "";
    $("#entry-username").value = entry?.username || "";
    $("#entry-password").value = entry?.password || "";
    $("#entry-notes").value = entry?.notes || "";
    $("#entry-password").type = "password";

    // Botones de copiar y eliminar solo cuando ya existe la entrada.
    const isExisting = !!entry;
    $("#detail-actions").hidden = !isExisting;
    $("#entry-delete").hidden = !isExisting;
    if (isExisting) {
      $("#detail-copy-user").onclick = () => copyClip(entry.username, "Usuario copiado");
      $("#detail-copy-pass").onclick = () => copyClip(entry.password, "Contraseña copiada (se borra en 20s)", true);
      $("#entry-delete").onclick = async () => {
        dlg.close();
        await deleteEntry(entry.id);
      };
    }
    dlg.showModal();
  }

  async function saveEntryFromForm() {
    const id = $("#entry-id").value || crypto.randomUUID();
    const data = {
      id,
      title: $("#entry-title").value.trim(),
      url: $("#entry-url").value.trim(),
      username: $("#entry-username").value.trim(),
      password: $("#entry-password").value,
      notes: $("#entry-notes").value,
      updatedAt: new Date().toISOString(),
    };
    const idx = entries.findIndex((en) => en.id === id);
    if (idx >= 0) entries[idx] = data; else entries.push(data);
    render($("#search").value);
    toast("Guardado", "ok");
    await pushVault();
  }

  async function deleteEntry(id) {
    const idx = entries.findIndex((x) => x.id === id && !x.deleted);
    if (idx < 0) return;
    if (!confirm(`¿Eliminar "${entries[idx].title}"? Esta acción no se puede deshacer.`)) return;
    // Tombstone: marca como borrada para que la eliminación se propague y no reviva.
    entries[idx] = { id, deleted: true, updatedAt: new Date().toISOString() };
    render($("#search").value);
    toast("Eliminado");
    await pushVault();
  }

  // =====================================================================
  // PORTAPAPELES (con auto-borrado para contraseñas)
  // =====================================================================
  async function copyClip(text, msg, autoClear = false) {
    if (!text) return toast("Vacío");
    try {
      await navigator.clipboard.writeText(text);
      toast(msg, "ok");
      if (autoClear) {
        setTimeout(async () => {
          try {
            const cur = await navigator.clipboard.readText();
            if (cur === text) await navigator.clipboard.writeText("");
          } catch {}
        }, 20000);
      }
    } catch {
      toast("No se pudo copiar (permiso del navegador)");
    }
  }

  // =====================================================================
  // AJUSTES
  // =====================================================================
  function saveSettingsFromForm() {
    settings.autolockMin = Math.max(1, Number($("#autolock-min").value) || 5);
    localStorage.setItem(LS.SETTINGS, JSON.stringify({ autolockMin: settings.autolockMin }));
    resetAutolock();
    toast("Ajustes guardados", "ok");
  }

  // =====================================================================
  // CAMBIAR CONTRASEÑA MAESTRA
  // =====================================================================
  function openPasswordDialog() {
    $("#new-password").value = "";
    $("#new-password-confirm").value = "";
    $("#new-password").type = "password";
    $("#new-strength-fill").style.width = "0%";
    $("#new-strength-label").textContent = "";
    hide($("#password-error"));
    $("#password-dialog").showModal();
  }

  async function changeMasterPassword() {
    const npw = $("#new-password").value;
    const conf = $("#new-password-confirm").value;
    const errEl = $("#password-error");
    hide(errEl);
    if (npw.length < 8) { errEl.textContent = "Usa al menos 8 caracteres (mejor una frase larga)."; show(errEl); return; }
    if (npw !== conf) { errEl.textContent = "Las contraseñas no coinciden."; show(errEl); return; }

    const btn = $("#password-save");
    btn.disabled = true;
    const prev = btn.textContent;
    btn.textContent = "…";
    try {
      const { encKey: newKey, authPassword } = await Vault.deriveKeys(npw, email);
      // 1) Cambia la clave de acceso en Supabase (la sesión sigue activa).
      await Cloud.updatePassword(authPassword);
      // 2) Re-cifra la bóveda con la nueva llave y guárdala (con reintentos).
      let saved = false, lastErr = null;
      for (let i = 0; i < 3 && !saved; i++) {
        try {
          const content = JSON.stringify(await Vault.encryptWithKey(newKey, { entries }));
          try { localStorage.setItem(cacheKey(), content); } catch {}
          await Cloud.saveVault(content);
          saved = true;
        } catch (e) {
          lastErr = e;
          await new Promise((r) => setTimeout(r, 800 * (i + 1)));
        }
      }
      if (!saved) {
        // Estado delicado: la clave ya cambió pero la bóveda no se re-cifró.
        // Pulsar "Cambiar" de nuevo es seguro (es idempotente) y reintenta.
        throw new Error("Contraseña cambiada, pero no se pudo re-cifrar la bóveda. NO cierres la app y pulsa Cambiar otra vez. (" + (lastErr && lastErr.message) + ")");
      }
      encKey = newKey;
      $("#password-dialog").close();
      toast("Contraseña maestra cambiada ✓", "ok");
    } catch (err) {
      errEl.textContent = err.message || "No se pudo cambiar la contraseña.";
      show(errEl);
    } finally {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }

  // =====================================================================
  // EXPORTAR / IMPORTAR (respaldo cifrado)
  // =====================================================================
  async function exportVault() {
    if (!encKey) return;
    const file = await encryptCurrent();
    const blob = new Blob([JSON.stringify(file, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "boveda.respaldo.json";
    a.click();
    URL.revokeObjectURL(a.href);
    toast("Exportado (cifrado)", "ok");
  }

  async function importVault(file) {
    const text = await file.text();
    try {
      const parsed = JSON.parse(text);
      const data = await Vault.decryptWithKey(encKey, parsed); // verifica con tu llave
      const imported = Array.isArray(data.entries) ? data.entries : [];
      entries = mergeEntries(entries, imported);
      render($("#search").value);
      toast("Importado y fusionado ✓", "ok");
      await pushVault();
    } catch (err) {
      toast("No se pudo importar: " + err.message, "err");
    }
  }

  // =====================================================================
  // IMPORTACIÓN MASIVA (pegar texto / CSV / PDF / Word) — ordena y numera
  // =====================================================================
  let importParsed = [];

  function normalizeKey(k) {
    k = String(k || "").toLowerCase().trim();
    if (/(t[íi]tulo|title|servicio|service|sitio|site|nombre|name|cuenta|account|app|aplicaci)/.test(k)) return "title";
    if (/(usuario|user|correo|e-?mail|login)/.test(k)) return "username";
    if (/(contrase|password|pass|clave|pin|secret)/.test(k)) return "password";
    if (/(url|web|p[áa]gina|page|link|dominio)/.test(k)) return "url";
    if (/(nota|note|coment)/.test(k)) return "notes";
    return null;
  }

  function normalizeEntry(e) {
    if (!e) return null;
    const out = {
      title: (e.title || "").trim(),
      username: (e.username || "").trim(),
      password: (e.password || "").trim(),
      url: (e.url || "").trim(),
      notes: (e.notes || "").trim(),
    };
    if (!out.title && !out.username && !out.password && !out.url) return null;
    if (!out.title) out.title = out.username || out.url || "(sin título)";
    return out;
  }

  function splitDelim(line, delim) {
    if (delim === "\t" || delim === "|") return line.split(delim);
    const out = []; let cur = "", q = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (q) {
        if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; }
        else cur += ch;
      } else {
        if (ch === '"') q = true;
        else if (ch === delim) { out.push(cur); cur = ""; }
        else cur += ch;
      }
    }
    out.push(cur);
    return out;
  }

  function detectDelim(lines) {
    if (!lines.length) return null;
    for (const d of ["\t", ";", "|", ","]) {
      const withD = lines.filter((l) => l.split(d).length - 1 >= 1).length;
      if (withD >= Math.max(1, Math.ceil(lines.length * 0.6))) return d;
    }
    return null;
  }

  function parseKeyValueBlocks(rawLines) {
    const out = []; let cur = null;
    const flush = () => {
      const e = normalizeEntry(cur);
      if (e) out.push(e);
      cur = null;
    };
    for (const line of rawLines) {
      const t = line.trim();
      if (!t) { flush(); continue; }
      const m = t.match(/^([^:=]{1,30})[:=]\s*(.*)$/);
      if (m) {
        const key = normalizeKey(m[1]); const val = m[2].trim();
        if (key) { cur = cur || {}; cur[key] = cur[key] ? cur[key] + " " + val : val; continue; }
      }
      cur = cur || {};
      if (!cur.title) cur.title = t; else cur.notes = (cur.notes ? cur.notes + " " : "") + t;
    }
    flush();
    return out;
  }

  // Solo es encabezado si CADA celda no vacía es una etiqueta conocida (exacta).
  // Así valores como "correo@x.com" o "insta_user" no se confunden con columnas.
  function headerKey(cell) {
    const k = String(cell || "").toLowerCase().trim();
    if (!k) return "";
    const exact = {
      "titulo": "title", "título": "title", "title": "title", "servicio": "title",
      "service": "title", "sitio": "title", "site": "title", "nombre": "title",
      "name": "title", "cuenta": "title", "account": "title", "app": "title",
      "usuario": "username", "user": "username", "username": "username",
      "correo": "username", "email": "username", "e-mail": "username", "login": "username",
      "contrasena": "password", "contraseña": "password", "password": "password",
      "pass": "password", "clave": "password", "pin": "password",
      "url": "url", "web": "url", "pagina": "url", "página": "url", "link": "url", "dominio": "url",
      "nota": "notes", "notas": "notes", "note": "notes", "notes": "notes", "comentario": "notes",
    };
    return exact[k] || null;
  }
  function detectHeader(cols) {
    const mapped = cols.map(headerKey);
    const nonEmpty = cols.filter((c) => String(c).trim()).length;
    const matched = mapped.filter(Boolean).length;
    if (matched >= 2 && matched === nonEmpty) return mapped;
    return null;
  }

  function parseDelimited(lines, delim) {
    const rows = lines.map((l) => splitDelim(l, delim));
    let map = null, start = 0;
    const header = detectHeader(rows[0]);
    if (header) { map = header; start = 1; }
    const out = [];
    for (let i = start; i < rows.length; i++) {
      const cols = rows[i];
      if (cols.every((c) => !String(c).trim())) continue;
      let e = {};
      if (map) {
        map.forEach((k, idx) => { if (k && cols[idx] != null) e[k] = String(cols[idx]).trim(); });
        if (!e.title) { const idx = map.findIndex((k) => !k); if (idx >= 0 && cols[idx]) e.title = String(cols[idx]).trim(); }
      } else {
        e.title = (cols[0] || "").trim();
        e.username = (cols[1] || "").trim();
        e.password = (cols[2] || "").trim();
        e.url = (cols[3] || "").trim();
        e.notes = cols.slice(4).join(" ").trim();
      }
      const ne = normalizeEntry(e);
      if (ne) out.push(ne);
    }
    return out;
  }

  function lineToEntry(line) {
    const t = line.trim();
    if (!t) return null;
    const parts = t.split(/\s*[|\t;]\s*|\s{2,}|\s+[-–—]\s+|\s*,\s*/).map((s) => s.trim()).filter(Boolean);
    let e = {};
    if (parts.length <= 1) { e.title = t; }
    else {
      const rest = [];
      for (const p of parts) {
        if (!e.username && /\S+@\S+\.\S+/.test(p)) e.username = p;
        else if (!e.url && /^(https?:\/\/|www\.)/i.test(p)) e.url = p;
        else rest.push(p);
      }
      e.title = rest.shift() || e.username || e.url || "(sin título)";
      if (rest.length) e.password = rest.shift();
      if (rest.length) e.notes = rest.join(" ");
    }
    return normalizeEntry(e);
  }

  /** Analiza texto libre y devuelve entradas ordenadas. */
  function parseImport(text) {
    const raw = String(text || "").replace(/\r\n?/g, "\n").trim();
    if (!raw) return [];
    const allLines = raw.split("\n");
    const lines = allLines.map((l) => l.trim());

    const kvRe = /^\s*(t[íi]tulo|title|servicio|service|sitio|site|nombre|name|cuenta|account|app|usuario|user(name)?|correo|e-?mail|login|contrase[ñn]a|password|pass|clave|pin|url|web|p[áa]gina|nota|notas?|notes?)\s*[:=]/i;
    if (lines.filter((l) => kvRe.test(l)).length >= 2) return parseKeyValueBlocks(allLines);

    const nonEmpty = lines.filter(Boolean);
    const delim = detectDelim(nonEmpty);
    if (delim) return parseDelimited(nonEmpty, delim);

    return nonEmpty.map(lineToEntry).filter(Boolean);
  }

  // ---- Lectura de archivos (PDF / Word se cargan bajo demanda) ----
  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = src; s.onload = resolve;
      s.onerror = () => reject(new Error("no se pudo cargar el lector (¿sin conexión?)"));
      document.head.appendChild(s);
    });
  }

  async function extractPdf(file) {
    if (!window.pdfjsLib) {
      await loadScript("https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js");
      window.pdfjsLib.GlobalWorkerOptions.workerSrc =
        "https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js";
    }
    const data = await file.arrayBuffer();
    const pdf = await window.pdfjsLib.getDocument({ data }).promise;
    let text = "";
    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      const content = await page.getTextContent();
      text += content.items.map((it) => it.str).join(" ") + "\n";
    }
    return text;
  }

  async function extractDocx(file) {
    if (!window.mammoth) {
      await loadScript("https://cdn.jsdelivr.net/npm/mammoth@1.8.0/mammoth.browser.min.js");
    }
    const arrayBuffer = await file.arrayBuffer();
    const r = await window.mammoth.extractRawText({ arrayBuffer });
    return r.value || "";
  }

  async function extractText(file) {
    const name = (file.name || "").toLowerCase();
    if (name.endsWith(".pdf")) return extractPdf(file);
    if (name.endsWith(".docx")) return extractDocx(file);
    return file.text(); // txt, csv, y otros de texto
  }

  function openImportDialog() {
    $("#import-text").value = "";
    $("#import-preview").innerHTML = "";
    $("#import-preview").hidden = true;
    hide($("#import-error")); hide($("#import-status"));
    $("#import-confirm").hidden = true;
    importParsed = [];
    $("#import-dialog").showModal();
  }

  function analyzeImport() {
    hide($("#import-error"));
    const text = $("#import-text").value;
    if (!text.trim()) { $("#import-error").textContent = "Pega texto o sube un archivo primero."; show($("#import-error")); return; }
    importParsed = parseImport(text);
    renderImportPreview();
  }

  function renderImportPreview() {
    const box = $("#import-preview");
    box.innerHTML = "";
    if (!importParsed.length) {
      $("#import-error").textContent = "No pude detectar contraseñas. Revisa el formato (una por línea, o 'Título | usuario | contraseña').";
      show($("#import-error"));
      box.hidden = true;
      $("#import-confirm").hidden = true;
      return;
    }
    hide($("#import-error"));
    importParsed.forEach((e, i) => {
      const row = document.createElement("div");
      row.className = "imp-row";
      row.innerHTML = `
        <span class="imp-num">${i + 1}</span>
        <div class="imp-main">
          <div class="imp-title">${escapeHtml(e.title)}</div>
          <div class="imp-sub">${escapeHtml(e.username || "")}${e.password ? " · ••••••" : ""}${e.url ? " · " + escapeHtml(e.url) : ""}</div>
        </div>
        <button type="button" class="ghost danger imp-del" title="Quitar">✕</button>`;
      row.querySelector(".imp-del").onclick = () => { importParsed.splice(i, 1); renderImportPreview(); };
      box.appendChild(row);
    });
    box.hidden = false;
    const btn = $("#import-confirm");
    btn.hidden = false;
    btn.textContent = `Importar ${importParsed.length}`;
  }

  async function confirmImport() {
    if (!importParsed.length) return;
    const now = Date.now();
    const toAdd = importParsed.map((e, i) => ({
      id: crypto.randomUUID(),
      title: e.title, username: e.username, password: e.password, url: e.url, notes: e.notes,
      updatedAt: new Date(now + i).toISOString(),
    }));
    entries = mergeEntries(entries, toAdd);
    render($("#search").value);
    $("#import-dialog").close();
    toast(`Importadas ${toAdd.length} contraseñas ✓`, "ok");
    await pushVault();
  }

  // =====================================================================
  // EVENTOS GLOBALES
  // =====================================================================
  function wireGlobalEvents() {
    // Botones mostrar/ocultar contraseña
    document.addEventListener("click", (e) => {
      const b = e.target.closest(".reveal");
      if (!b) return;
      const inp = document.getElementById(b.dataset.target);
      if (inp) inp.type = inp.type === "password" ? "text" : "password";
    });

    $("#add-btn").onclick = () => openEntryDialog();
    $("#lock-now-btn").onclick = lock;
    $("#sync-btn").onclick = syncNow;
    $("#settings-btn").onclick = () => {
      $("#account-email").textContent = email;
      $("#autolock-min").value = settings.autolockMin || 5;
      $("#settings-dialog").showModal();
    };

    $("#search").addEventListener("input", (e) => render(e.target.value));

    // Modal entrada
    $("#entry-form").addEventListener("submit", () => saveEntryFromForm());
    $("#entry-cancel").onclick = () => $("#entry-dialog").close();
    // (los botones copiar/eliminar del detalle se conectan en openEntryDialog)
    $("#gen-btn").onclick = () => {
      const pw = Vault.generatePassword({ length: 20 });
      const inp = $("#entry-password");
      inp.value = pw;
      inp.type = "text";
    };

    // Modal ajustes
    $("#settings-form").addEventListener("submit", () => saveSettingsFromForm());
    $("#settings-cancel").onclick = () => $("#settings-dialog").close();
    $("#signout-btn").onclick = signOutFull;
    $("#change-pw-btn").onclick = openPasswordDialog;
    $("#export-btn").onclick = exportVault;

    // Diálogo cambiar contraseña maestra
    $("#password-form").addEventListener("submit", (e) => { e.preventDefault(); changeMasterPassword(); });
    $("#password-cancel").onclick = () => $("#password-dialog").close();
    $("#new-password").addEventListener("input", () => {
      const { score, label } = Vault.estimateStrength($("#new-password").value);
      $("#new-strength-fill").style.width = (score * 25) + "%";
      $("#new-strength-fill").dataset.score = score;
      $("#new-strength-label").textContent = label;
    });
    $("#import-btn").onclick = () => $("#import-file").click();
    $("#import-file").addEventListener("change", (e) => {
      if (e.target.files[0]) importVault(e.target.files[0]);
    });

    // Importación masiva (pegar / PDF / Word / texto)
    $("#bulk-import-btn").onclick = () => { $("#settings-dialog").close(); openImportDialog(); };
    $("#import-cancel").onclick = () => $("#import-dialog").close();
    $("#import-analyze").onclick = analyzeImport;
    $("#import-confirm").onclick = confirmImport;
    $("#import-file2-btn").onclick = () => $("#import-file2").click();
    $("#import-file2").addEventListener("change", async (e) => {
      const f = e.target.files[0];
      if (!f) return;
      hide($("#import-error"));
      $("#import-status").textContent = "Leyendo archivo…";
      show($("#import-status"));
      try {
        const text = await extractText(f);
        $("#import-text").value = text;
        hide($("#import-status"));
        analyzeImport();
      } catch (err) {
        hide($("#import-status"));
        $("#import-error").textContent = "No se pudo leer el archivo: " + (err.message || err);
        show($("#import-error"));
      }
      e.target.value = "";
    });

    // Reinicia el temporizador de auto-bloqueo con actividad del usuario.
    ["click", "keydown", "mousemove"].forEach((ev) =>
      document.addEventListener(ev, () => { if (encKey) resetAutolock(); }, { passive: true })
    );
  }

  // ---- Escapado seguro para insertar en HTML ----
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function escapeAttr(s) { return escapeHtml(s); }

  /**
   * Devuelve una URL segura para href, o "" si no lo es.
   * Solo http/https (bloquea javascript:, data:, etc.). Si no hay esquema, https://.
   */
  function safeUrl(u) {
    const raw = (u || "").trim();
    if (!raw) return "";
    const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw) ? raw : "https://" + raw;
    try {
      const parsed = new URL(candidate);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") return candidate;
    } catch {}
    return "";
  }

  document.addEventListener("DOMContentLoaded", init);
})();

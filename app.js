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

    for (const en of items) {
      const card = document.createElement("article");
      card.className = "entry";
      const href = safeUrl(en.url);
      card.innerHTML = `
        <div class="entry-main">
          <div class="entry-title">${escapeHtml(en.title || "(sin título)")}</div>
          <div class="entry-sub">${escapeHtml(en.username || "")}</div>
          ${href ? `<a class="entry-url" href="${escapeAttr(href)}" target="_blank" rel="noopener">${escapeHtml(en.url)}</a>` : ""}
        </div>
        <div class="entry-actions">
          <button class="ghost" data-act="copy-user" title="Copiar usuario">👤</button>
          <button class="ghost" data-act="copy-pass" title="Copiar contraseña">🔑</button>
          <button class="ghost" data-act="edit" title="Editar">✏</button>
          <button class="ghost danger" data-act="del" title="Eliminar">🗑</button>
        </div>`;
      card.querySelector('[data-act="copy-user"]').onclick = () => copyClip(en.username, "Usuario copiado");
      card.querySelector('[data-act="copy-pass"]').onclick = () => copyClip(en.password, "Contraseña copiada (se borra en 20s)", true);
      card.querySelector('[data-act="edit"]').onclick = () => openEntryDialog(en);
      card.querySelector('[data-act="del"]').onclick = () => deleteEntry(en.id);
      list.appendChild(card);
    }
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

/*
 * app.js — Orquestación de la UI, estado en memoria y persistencia.
 *
 * Estado sensible (contraseña maestra, entradas descifradas) vive SOLO en memoria
 * mientras el baúl está desbloqueado. Al bloquear se limpia.
 *
 * Persistencia local: el ARCHIVO CIFRADO se guarda en localStorage como respaldo
 * offline. La contraseña maestra jamás se guarda.
 */

(() => {
  "use strict";

  const LS = {
    VAULT: "baul.vault",        // archivo cifrado (respaldo local)
    SETTINGS: "baul.settings",  // ajustes de sync (sin token, salvo "recordar")
    TOKEN: "baul.gh_token",     // token (solo si el usuario marca "recordar")
    SHA: "baul.gh_sha",         // sha del archivo remoto para actualizaciones
  };

  // ---- Estado en memoria (se borra al bloquear) ----
  let masterPassword = null;
  let entries = [];          // [{ id, title, url, username, password, notes, updatedAt }]
  let settings = { repo: "", path: "baul.vault.json", branch: "main", autolockMin: 5 };
  let ghToken = "";
  let remoteSha = null;
  let autolockTimer = null;

  // ---- Helpers DOM ----
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

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

  // =====================================================================
  // ARRANQUE
  // =====================================================================
  function init() {
    loadSettings();
    const hasVault = !!localStorage.getItem(LS.VAULT);
    setupLockScreen(hasVault);
    wireGlobalEvents();
  }

  function loadSettings() {
    try {
      const s = JSON.parse(localStorage.getItem(LS.SETTINGS) || "{}");
      settings = { ...settings, ...s };
    } catch {}
    ghToken = localStorage.getItem(LS.TOKEN) || "";
    remoteSha = localStorage.getItem(LS.SHA) || null;
  }

  // =====================================================================
  // PANTALLA DE BLOQUEO
  // =====================================================================
  function setupLockScreen(hasVault) {
    const subtitle = $("#lock-subtitle");
    const confirmField = $("#confirm-field");
    const strength = $("#strength");
    const newWarn = $("#new-vault-warn");
    const btn = $("#unlock-btn");

    if (hasVault) {
      subtitle.textContent = "Ingresa tu contraseña maestra";
      btn.textContent = "Desbloquear";
      hide(confirmField); hide(strength); hide(newWarn);
    } else {
      subtitle.textContent = "Crea tu contraseña maestra";
      btn.textContent = "Crear baúl";
      show(confirmField); show(strength); show(newWarn);
    }

    const pwInput = $("#master-password");
    pwInput.addEventListener("input", () => {
      if (confirmField.hidden) return;
      const { score, label } = Vault.estimateStrength(pwInput.value);
      $("#strength-fill").style.width = (score * 25) + "%";
      $("#strength-fill").dataset.score = score;
      $("#strength-label").textContent = label;
    });

    $("#unlock-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      hide($("#lock-error"));
      const pw = pwInput.value;
      if (!pw) return;

      if (!hasVault) {
        // Crear baúl nuevo
        const confirm = $("#master-password-confirm").value;
        if (pw !== confirm) return lockError("Las contraseñas no coinciden.");
        if (pw.length < 8) return lockError("Usa al menos 8 caracteres (idealmente una frase larga).");
        masterPassword = pw;
        entries = [];
        await saveVault();
        openMain();
      } else {
        // Desbloquear baúl existente
        btnBusy(true);
        try {
          const file = JSON.parse(localStorage.getItem(LS.VAULT));
          const data = await Vault.decryptVault(pw, file);
          masterPassword = pw;
          entries = Array.isArray(data.entries) ? data.entries : [];
          openMain();
        } catch (err) {
          lockError(err.message || "No se pudo desbloquear.");
        } finally {
          btnBusy(false);
        }
      }
    });
  }

  function lockError(msg) {
    const e = $("#lock-error");
    e.textContent = msg;
    show(e);
  }
  function btnBusy(b) {
    const btn = $("#unlock-btn");
    btn.disabled = b;
    btn.textContent = b ? "…" : (localStorage.getItem(LS.VAULT) ? "Desbloquear" : "Crear baúl");
  }

  // =====================================================================
  // BLOQUEO / DESBLOQUEO
  // =====================================================================
  function openMain() {
    $("#master-password").value = "";
    const c = $("#master-password-confirm"); if (c) c.value = "";
    hide($("#lock-screen"));
    show($("#main-screen"));
    fillSettingsForm();
    render();
    resetAutolock();
    // Intento silencioso de bajar cambios remotos al abrir.
    if (settings.repo && ghToken) syncPull(true);
  }

  function lock() {
    // Limpia todo lo sensible de memoria Y del DOM.
    masterPassword = null;
    entries = [];
    clearTimeout(autolockTimer);
    $("#entries").innerHTML = ""; // elimina tarjetas y closures con contraseñas
    $("#search").value = "";
    hide($("#main-screen"));
    show($("#lock-screen"));
    setupLockScreen(!!localStorage.getItem(LS.VAULT));
    $("#master-password").focus();
  }

  function resetAutolock() {
    clearTimeout(autolockTimer);
    const min = Math.max(1, Number(settings.autolockMin) || 5);
    autolockTimer = setTimeout(lock, min * 60 * 1000);
  }

  // =====================================================================
  // PERSISTENCIA (cifrar + guardar)
  // =====================================================================
  async function saveVault({ pushRemote = false } = {}) {
    if (masterPassword == null) return;
    const file = await Vault.encryptVault(masterPassword, { entries });
    const contentStr = JSON.stringify(file, null, 2);
    localStorage.setItem(LS.VAULT, contentStr);
    if (pushRemote && settings.repo && ghToken) {
      await syncPush(contentStr);
    }
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

  async function saveEntryFromForm(e) {
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
    await saveVault({ pushRemote: true });
    render($("#search").value);
    toast("Guardado", "ok");
  }

  async function deleteEntry(id) {
    const idx = entries.findIndex((x) => x.id === id && !x.deleted);
    if (idx < 0) return;
    if (!confirm(`¿Eliminar "${entries[idx].title}"? Esta acción no se puede deshacer.`)) return;
    // Tombstone: marca como borrada en vez de quitarla, para que al fusionar
    // con otro dispositivo (o el remoto) la eliminación no se revierta.
    // Se limpian los datos sensibles; solo queda id/deleted/updatedAt.
    entries[idx] = { id, deleted: true, updatedAt: new Date().toISOString() };
    await saveVault({ pushRemote: true });
    render($("#search").value);
    toast("Eliminado");
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
  function fillSettingsForm() {
    $("#gh-repo").value = settings.repo || "";
    $("#gh-path").value = settings.path || "baul.vault.json";
    $("#gh-branch").value = settings.branch || "main";
    $("#gh-token").value = ghToken || "";
    $("#gh-remember").checked = !!localStorage.getItem(LS.TOKEN);
    $("#autolock-min").value = settings.autolockMin || 5;
  }

  function saveSettingsFromForm() {
    settings.repo = $("#gh-repo").value.trim();
    settings.path = $("#gh-path").value.trim() || "baul.vault.json";
    settings.branch = $("#gh-branch").value.trim() || "main";
    settings.autolockMin = Math.max(1, Number($("#autolock-min").value) || 5);
    ghToken = $("#gh-token").value.trim();

    localStorage.setItem(LS.SETTINGS, JSON.stringify({
      repo: settings.repo, path: settings.path,
      branch: settings.branch, autolockMin: settings.autolockMin,
    }));
    if ($("#gh-remember").checked && ghToken) {
      localStorage.setItem(LS.TOKEN, ghToken);
    } else {
      localStorage.removeItem(LS.TOKEN);
    }
    resetAutolock();
    toast("Ajustes guardados", "ok");
  }

  // =====================================================================
  // SINCRONIZACIÓN
  // =====================================================================
  function syncMsg(msg, kind = "") {
    const el = $("#sync-status");
    el.textContent = msg;
    el.className = "sync-status " + kind;
    el.hidden = false;
    if (kind === "ok") setTimeout(() => (el.hidden = true), 2500);
  }

  /**
   * Fusiona dos listas de entradas SIN perder datos.
   * Regla: por cada id gana la versión con updatedAt más reciente.
   * Los tombstones (deleted) participan igual, así una eliminación reciente
   * no revive al fusionar con un dispositivo que aún tenía la entrada.
   */
  function mergeEntries(a, b) {
    const map = new Map();
    for (const en of [...(a || []), ...(b || [])]) {
      if (!en || !en.id) continue;
      const prev = map.get(en.id);
      if (!prev || (en.updatedAt || "") >= (prev.updatedAt || "")) {
        map.set(en.id, en);
      }
    }
    return [...map.values()];
  }

  async function syncPull(silent = false) {
    if (!settings.repo || !ghToken) {
      if (!silent) toast("Configura GitHub en Ajustes");
      return;
    }
    try {
      if (!silent) syncMsg("Bajando del repo…");
      const cfg = { ...settings, token: ghToken };
      const remote = await GitHubSync.pull(cfg);
      if (!remote) { if (!silent) syncMsg("No hay baúl remoto todavía.", "ok"); return; }

      const file = JSON.parse(remote.content);
      const data = await Vault.decryptVault(masterPassword, file);
      const remoteEntries = Array.isArray(data.entries) ? data.entries : [];
      // FUSIÓN: nunca sobreescribe lo local; combina por id/updatedAt.
      entries = mergeEntries(entries, remoteEntries);
      remoteSha = remote.sha;
      localStorage.setItem(LS.SHA, remoteSha);
      // Guarda localmente el resultado de la fusión (re-cifrado con la maestra).
      await saveVault();
      render($("#search").value);
      if (!silent) syncMsg("Sincronizado desde GitHub ✓", "ok");
    } catch (err) {
      syncMsg("Error al bajar: " + err.message, "err");
    }
  }

  async function syncPush(contentStr) {
    try {
      syncMsg("Subiendo al repo…");
      const cfg = { ...settings, token: ghToken };
      const newSha = await GitHubSync.push(cfg, contentStr, remoteSha);
      remoteSha = newSha;
      localStorage.setItem(LS.SHA, remoteSha);
      syncMsg("Guardado en GitHub ✓", "ok");
    } catch (err) {
      syncMsg("Error al subir: " + err.message + " (guardado localmente)", "err");
    }
  }

  async function syncNow() {
    // Baja y FUSIONA con lo local, luego sube el baúl ya fusionado.
    // Así dos dispositivos no se pisan: se combinan sus cambios por updatedAt.
    if (!settings.repo || !ghToken) return toast("Configura GitHub en Ajustes");
    await syncPull();
    await saveVault({ pushRemote: true });
  }

  // =====================================================================
  // EXPORTAR / IMPORTAR (respaldo cifrado)
  // =====================================================================
  function exportVault() {
    const content = localStorage.getItem(LS.VAULT);
    if (!content) return toast("Nada que exportar");
    const blob = new Blob([content], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "baul.vault.json";
    a.click();
    URL.revokeObjectURL(a.href);
    toast("Exportado (cifrado)", "ok");
  }

  async function importVault(file) {
    const text = await file.text();
    try {
      const parsed = JSON.parse(text);
      // Verifica que se descifre con la contraseña actual antes de aceptar.
      const data = await Vault.decryptVault(masterPassword, parsed);
      entries = Array.isArray(data.entries) ? data.entries : [];
      localStorage.setItem(LS.VAULT, text);
      render($("#search").value);
      toast("Importado ✓", "ok");
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
    $("#settings-btn").onclick = () => { fillSettingsForm(); $("#settings-dialog").showModal(); };

    $("#search").addEventListener("input", (e) => render(e.target.value));

    // Modal entrada
    $("#entry-form").addEventListener("submit", (e) => {
      // method=dialog: no recarga; guardamos y dejamos que se cierre.
      saveEntryFromForm(e);
    });
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
    $("#export-btn").onclick = exportVault;
    $("#import-btn").onclick = () => $("#import-file").click();
    $("#import-file").addEventListener("change", (e) => {
      if (e.target.files[0]) importVault(e.target.files[0]);
    });

    // Reinicia el temporizador de auto-bloqueo con actividad del usuario.
    ["click", "keydown", "mousemove"].forEach((ev) =>
      document.addEventListener(ev, () => { if (masterPassword) resetAutolock(); }, { passive: true })
    );
  }

  // ---- Escapado seguro para insertar en HTML ----
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function escapeAttr(s) { return escapeHtml(s); }

  /**
   * Devuelve una URL segura para usar en href, o "" si no lo es.
   * Solo se permiten http/https (bloquea javascript:, data:, etc.).
   * Si el usuario no escribió esquema, se asume https://.
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

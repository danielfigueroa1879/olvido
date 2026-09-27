/*
 * github.js — Sincronización del baúl CIFRADO con un repositorio privado.
 *
 * Usa la GitHub REST API (Contents endpoint). El navegador solo sube/baja el
 * archivo ya cifrado, así que GitHub jamás ve las contraseñas en claro.
 *
 * Requiere un fine-grained Personal Access Token con:
 *   - Acceso solo al repo del baúl.
 *   - Permiso "Contents": Read and write.
 *
 * Config: { repo: "usuario/repo", path: "baul.vault.json", branch: "main", token }
 */

const GitHubSync = (() => {
  const API = "https://api.github.com";

  function headers(token) {
    return {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    };
  }

  function validate(cfg) {
    if (!cfg || !cfg.repo || !cfg.path || !cfg.token) {
      throw new Error("Configura repo, ruta y token en Ajustes.");
    }
    if (!/^[^/\s]+\/[^/\s]+$/.test(cfg.repo)) {
      throw new Error('El repo debe tener el formato "usuario/repo".');
    }
  }

  // Codifica texto UTF-8 a base64 (para el campo content de la API).
  function utf8ToB64(str) {
    const bytes = new TextEncoder().encode(str);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }
  function b64ToUtf8(b64) {
    const bin = atob(b64.replace(/\n/g, ""));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  /**
   * Descarga el archivo del baúl desde el repo.
   * @returns {Promise<{content: string, sha: string} | null>} null si no existe aún.
   */
  async function pull(cfg) {
    validate(cfg);
    const branch = cfg.branch || "main";
    const url = `${API}/repos/${cfg.repo}/contents/${encodeURIComponent(cfg.path)}?ref=${encodeURIComponent(branch)}`;
    const res = await fetch(url, { headers: headers(cfg.token) });
    if (res.status === 404) return null; // baúl remoto aún no creado
    if (res.status === 401) throw new Error("Token inválido o sin permisos.");
    if (!res.ok) throw new Error(`GitHub (pull): ${res.status} ${res.statusText}`);
    const json = await res.json();
    return { content: b64ToUtf8(json.content), sha: json.sha };
  }

  /**
   * Sube (crea o actualiza) el archivo del baúl.
   * @param {object} cfg
   * @param {string} contentStr  contenido de texto (JSON del baúl CIFRADO)
   * @param {string|null} sha     sha actual del archivo remoto (null si es nuevo)
   * @returns {Promise<string>} nuevo sha
   */
  async function push(cfg, contentStr, sha) {
    validate(cfg);
    const branch = cfg.branch || "main";
    const url = `${API}/repos/${cfg.repo}/contents/${encodeURIComponent(cfg.path)}`;
    const body = {
      message: `Actualizar baúl · ${new Date().toISOString()}`,
      content: utf8ToB64(contentStr),
      branch,
    };
    if (sha) body.sha = sha;
    const res = await fetch(url, {
      method: "PUT",
      headers: { ...headers(cfg.token), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (res.status === 409) {
      throw new Error("Conflicto: el baúl remoto cambió. Sincroniza (bajar) primero.");
    }
    if (res.status === 401) throw new Error("Token inválido o sin permisos.");
    if (!res.ok) {
      const t = await res.text();
      throw new Error(`GitHub (push): ${res.status} ${t.slice(0, 120)}`);
    }
    const json = await res.json();
    return json.content.sha;
  }

  return { pull, push, validate };
})();

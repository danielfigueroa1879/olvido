/*
 * crypto.js — Cifrado zero-knowledge del baúl.
 *
 * Modelo de seguridad:
 *   - La contraseña maestra NUNCA se guarda ni se transmite.
 *   - De ella se deriva una llave con PBKDF2-HMAC-SHA256 (muchas iteraciones).
 *   - El baúl se cifra con AES-256-GCM (cifrado + autenticación/anti-manipulación).
 *   - salt e iv son aleatorios y se guardan junto al texto cifrado (no son secretos).
 *   - Todo corre en el navegador con la Web Crypto API nativa.
 *
 * Formato del archivo del baúl (JSON, texto plano de la ESTRUCTURA, no del contenido):
 *   {
 *     "version": 1,
 *     "kdf": "PBKDF2-SHA256",
 *     "iterations": 600000,
 *     "salt": "<base64>",
 *     "iv": "<base64>",
 *     "ciphertext": "<base64>"   // AES-GCM de { entries: [...] }
 *   }
 */

const Vault = (() => {
  const VERSION = 1;
  const KDF = "PBKDF2-SHA256";
  // OWASP (2023) recomienda >= 600.000 iteraciones para PBKDF2-HMAC-SHA256.
  const ITERATIONS = 600_000;
  const SALT_BYTES = 16;
  const IV_BYTES = 12; // 96 bits, recomendado para AES-GCM

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---- Helpers base64 <-> ArrayBuffer ----
  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function b64ToBuf(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  // ---- Derivación de llave desde la contraseña maestra ----
  async function deriveKey(password, salt, iterations = ITERATIONS) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false, // no exportable: la llave no puede salir del navegador
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Crea un baúl cifrado nuevo (o re-cifra datos existentes) con una contraseña.
   * @param {string} password  contraseña maestra
   * @param {object} data       { entries: [...] }
   * @returns {object} estructura del archivo del baúl
   */
  async function encryptVault(password, data) {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const key = await deriveKey(password, salt);
    const plaintext = enc.encode(JSON.stringify(data));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      plaintext
    );
    return {
      version: VERSION,
      kdf: KDF,
      iterations: ITERATIONS,
      salt: bufToB64(salt),
      iv: bufToB64(iv),
      ciphertext: bufToB64(ciphertext),
    };
  }

  /**
   * Descifra un baúl. Lanza error si la contraseña es incorrecta o el archivo
   * fue manipulado (AES-GCM falla la verificación de integridad).
   * @returns {object} data descifrado { entries: [...] }
   */
  async function decryptVault(password, file) {
    if (!file || file.version !== VERSION) {
      throw new Error("Formato de baúl no reconocido.");
    }
    const salt = new Uint8Array(b64ToBuf(file.salt));
    const iv = new Uint8Array(b64ToBuf(file.iv));
    const key = await deriveKey(password, salt, file.iterations || ITERATIONS);
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        b64ToBuf(file.ciphertext)
      );
      return JSON.parse(dec.decode(plaintext));
    } catch (e) {
      // GCM lanza si la llave (contraseña) es incorrecta o el dato fue alterado.
      throw new Error("Contraseña maestra incorrecta o archivo dañado.");
    }
  }

  // ---- Generador de contraseñas fuertes (aleatoriedad criptográfica) ----
  function generatePassword(opts = {}) {
    const {
      length = 20,
      lower = true,
      upper = true,
      digits = true,
      symbols = true,
    } = opts;
    let pool = "";
    if (lower) pool += "abcdefghijkmnopqrstuvwxyz"; // sin l
    if (upper) pool += "ABCDEFGHJKLMNPQRSTUVWXYZ"; // sin I, O
    if (digits) pool += "23456789"; // sin 0,1
    if (symbols) pool += "!@#$%^&*()-_=+[]{}?";
    if (!pool) pool = "abcdefghijklmnopqrstuvwxyz";
    const out = new Array(length);
    const rnd = crypto.getRandomValues(new Uint32Array(length));
    for (let i = 0; i < length; i++) out[i] = pool[rnd[i] % pool.length];
    return out.join("");
  }

  // ---- Estimación simple de fortaleza (para la UI) ----
  function estimateStrength(password) {
    if (!password) return { score: 0, label: "" };
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(password)) pool += 30;
    const entropy = password.length * Math.log2(pool || 1);
    let score, label;
    if (entropy < 40) { score = 1; label = "Débil"; }
    else if (entropy < 60) { score = 2; label = "Aceptable"; }
    else if (entropy < 80) { score = 3; label = "Fuerte"; }
    else { score = 4; label = "Muy fuerte"; }
    return { score, label, entropy: Math.round(entropy) };
  }

  return {
    encryptVault,
    decryptVault,
    generatePassword,
    estimateStrength,
  };
})();

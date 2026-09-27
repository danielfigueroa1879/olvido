/*
 * crypto.js — Criptografía zero-knowledge de la bóveda (modelo multiusuario).
 *
 * De la contraseña maestra + el correo se derivan DOS llaves separadas:
 *   1) encKey       -> AES-256-GCM, cifra/descifra la bóveda (NUNCA sale del navegador).
 *   2) authPassword -> hash que se usa como "contraseña" ante Supabase para iniciar
 *                      sesión. El servidor solo ve este hash, jamás tu contraseña real
 *                      ni la llave de cifrado. Aunque la base de datos se filtre, la
 *                      bóveda sigue cifrada y es indescifrable sin tu contraseña.
 *
 * Derivación (determinista para que cualquier dispositivo obtenga las mismas llaves):
 *   masterBits   = PBKDF2-SHA256(password, salt = "baul.v2:" + correo, 600.000)
 *   encKey       = HKDF-SHA256(masterBits, info = "enc")   -> AES-256-GCM
 *   authPassword = HKDF-SHA256(masterBits, info = "auth")  -> hex de 64 chars
 *
 * Formato del archivo cifrado que se guarda en la nube (JSON):
 *   { "version": 2, "iv": "<base64>", "ciphertext": "<base64>" }
 *   (No hace falta guardar salt: se recalcula desde el correo. El iv es aleatorio
 *    por cada guardado, como exige AES-GCM.)
 */

const Vault = (() => {
  const ITERATIONS = 600_000; // OWASP 2023 para PBKDF2-HMAC-SHA256
  const IV_BYTES = 12;        // 96 bits, recomendado para AES-GCM

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // Constantes públicas (no secretas) para HKDF.
  const HKDF_SALT = enc.encode("baul.v2.hkdf.salt");
  const ENC_INFO = enc.encode("baul.v2.enc");
  const AUTH_INFO = enc.encode("baul.v2.auth");

  // ---- Helpers base64 / hex <-> ArrayBuffer ----
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
  function bufToHex(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
    return s;
  }

  // ---- Derivación de llaves desde contraseña + correo ----
  async function deriveMasterBits(password, email) {
    const baseKey = await crypto.subtle.importKey(
      "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
    );
    const salt = enc.encode("baul.v2:" + String(email || "").trim().toLowerCase());
    return crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
      baseKey, 256
    );
  }

  /**
   * Deriva las dos llaves. Determinista: mismo (correo, contraseña) => mismas llaves,
   * en cualquier dispositivo.
   * @returns {Promise<{encKey: CryptoKey, authPassword: string}>}
   */
  async function deriveKeys(password, email) {
    const masterBits = await deriveMasterBits(password, email);
    const hkdfKey = await crypto.subtle.importKey(
      "raw", masterBits, { name: "HKDF" }, false, ["deriveKey", "deriveBits"]
    );
    const encKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: ENC_INFO },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false, // no exportable
      ["encrypt", "decrypt"]
    );
    const authBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: AUTH_INFO },
      hkdfKey, 256
    );
    return { encKey, authPassword: bufToHex(authBits) };
  }

  // ---- Cifrado / descifrado con una llave ya derivada ----
  async function encryptWithKey(encKey, data) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, encKey, enc.encode(JSON.stringify(data))
    );
    return { version: 2, iv: bufToB64(iv), ciphertext: bufToB64(ciphertext) };
  }

  async function decryptWithKey(encKey, file) {
    if (!file || file.version !== 2 || !file.iv || !file.ciphertext) {
      throw new Error("Formato de bóveda no reconocido.");
    }
    const iv = new Uint8Array(b64ToBuf(file.iv));
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv }, encKey, b64ToBuf(file.ciphertext)
      );
      return JSON.parse(dec.decode(plaintext));
    } catch (e) {
      // GCM falla si la llave (contraseña) es incorrecta o el dato fue alterado.
      throw new Error("Contraseña maestra incorrecta o datos dañados.");
    }
  }

  // ---- Generador de contraseñas fuertes (aleatoriedad criptográfica) ----
  function generatePassword(opts = {}) {
    const {
      length = 20, lower = true, upper = true, digits = true, symbols = true,
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
    deriveKeys,
    encryptWithKey,
    decryptWithKey,
    generatePassword,
    estimateStrength,
  };
})();

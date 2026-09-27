/*
 * supabase.js — Capa de nube (autenticación + almacenamiento de la bóveda cifrada).
 *
 * Usa la librería oficial @supabase/supabase-js (cargada por CDN en index.html,
 * expone window.supabase.createClient).
 *
 * - Autenticación: correo + una contraseña de sesión (authPassword) que es un hash
 *   derivado de tu contraseña maestra. Supabase NUNCA recibe tu contraseña real.
 * - Almacenamiento: tabla "vaults", una fila por usuario, con el texto CIFRADO.
 *   Los permisos (RLS) garantizan que cada quien solo lee/escribe su propia fila.
 */

const Cloud = (() => {
  let client = null;

  function configured() {
    const url = window.SUPABASE_URL || "";
    const key = window.SUPABASE_ANON_KEY || "";
    return !!url && !!key && !/TU_.*_AQUI/.test(url) && !/TU_.*_AQUI/.test(key);
  }

  function getClient() {
    if (client) return client;
    if (!window.supabase || !window.supabase.createClient) {
      throw new Error("No se pudo cargar la librería de Supabase (¿sin conexión?).");
    }
    if (!configured()) {
      throw new Error("Falta configurar Supabase en config.js.");
    }
    client = window.supabase.createClient(window.SUPABASE_URL, window.SUPABASE_ANON_KEY, {
      auth: { persistSession: true, autoRefreshToken: true },
    });
    return client;
  }

  // Traduce errores comunes de Supabase a mensajes claros en español.
  function friendly(error) {
    const msg = (error && error.message) || String(error || "Error");
    if (/invalid login credentials/i.test(msg)) return "Correo o contraseña incorrectos.";
    if (/email not confirmed/i.test(msg)) return "Debes confirmar tu correo antes de entrar (revisa tu bandeja).";
    if (/user already registered/i.test(msg)) return "Ese correo ya tiene una cuenta. Inicia sesión.";
    if (/password should be at least/i.test(msg)) return "La contraseña es demasiado corta.";
    if (/rate limit|too many/i.test(msg)) return "Demasiados intentos. Espera un momento e inténtalo de nuevo.";
    if (/failed to fetch|networkerror|load failed/i.test(msg)) return "Sin conexión con el servidor.";
    return msg;
  }

  async function signUp(email, authPassword) {
    const { data, error } = await getClient().auth.signUp({ email, password: authPassword });
    if (error) throw new Error(friendly(error));
    return data;
  }

  async function signIn(email, authPassword) {
    const { data, error } = await getClient().auth.signInWithPassword({ email, password: authPassword });
    if (error) throw new Error(friendly(error));
    return data;
  }

  async function signOut() {
    try { await getClient().auth.signOut(); } catch {}
  }

  /** Cambia la "contraseña" (hash de acceso) de la sesión actual en Supabase. */
  async function updatePassword(newAuthPassword) {
    const { error } = await getClient().auth.updateUser({ password: newAuthPassword });
    if (error) throw new Error(friendly(error));
  }

  async function getSession() {
    if (!configured()) return null;
    try {
      const { data } = await getClient().auth.getSession();
      return data.session || null;
    } catch { return null; }
  }

  async function currentUser() {
    const { data } = await getClient().auth.getUser();
    return data.user || null;
  }

  /**
   * Descarga la fila del usuario actual.
   * @returns {Promise<{content:string, updated_at:string} | null>} null si aún no existe.
   */
  async function loadVault() {
    const u = await currentUser();
    if (!u) return null;
    const { data, error } = await getClient()
      .from("vaults")
      .select("content, updated_at")
      .eq("user_id", u.id)
      .maybeSingle();
    if (error) throw new Error(friendly(error));
    return data || null;
  }

  /** Crea o actualiza la fila cifrada del usuario actual. */
  async function saveVault(content) {
    const u = await currentUser();
    if (!u) throw new Error("Tu sesión expiró. Vuelve a iniciar sesión.");
    const { error } = await getClient()
      .from("vaults")
      .upsert(
        { user_id: u.id, content, updated_at: new Date().toISOString() },
        { onConflict: "user_id" }
      );
    if (error) throw new Error(friendly(error));
  }

  return {
    configured, signUp, signIn, signOut, updatePassword,
    getSession, currentUser, loadVault, saveVault,
  };
})();

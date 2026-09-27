/*
 * config.js — Configuración de la nube (Supabase).
 *
 * Pega aquí los datos de TU proyecto de Supabase. Se hacen UNA sola vez y
 * quedan dentro de la app publicada, así en cada dispositivo solo escribes
 * tu correo y contraseña (no vuelves a configurar nada).
 *
 * ¿De dónde salen estos dos valores?
 *   En https://supabase.com  ->  tu proyecto  ->  Settings  ->  API
 *     - Project URL           -> SUPABASE_URL
 *     - Project API keys -> anon public  -> SUPABASE_ANON_KEY
 *
 * La clave "anon" es PÚBLICA por diseño: no da acceso a los datos de nadie,
 * porque cada bóveda está protegida por permisos por usuario (RLS) en Supabase
 * y, además, va cifrada. Ver README.md para el paso a paso.
 */

window.SUPABASE_URL = "TU_PROJECT_URL_AQUI";
window.SUPABASE_ANON_KEY = "TU_ANON_KEY_AQUI";

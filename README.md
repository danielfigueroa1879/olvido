# 🔐 Bóveda — Gestor de contraseñas en la nube (zero-knowledge)

Una sola bóveda por usuario, en la nube. Inicias sesión con **correo + contraseña
maestra** desde el celular, la tablet o el PC y **siempre ves las mismas
contraseñas**. No hay que crear nada nuevo en cada dispositivo.

Tu contraseña maestra **nunca** viaja al servidor: de ella se derivan dos llaves
distintas (una para entrar y otra para cifrar), todo en tu dispositivo. A la nube
solo sube el archivo **ya cifrado**, así que el servidor jamás ve tus contraseñas.

## Cómo funciona la seguridad

| Qué | Cómo |
|-----|------|
| Derivación de llaves | PBKDF2-HMAC-SHA256 (600.000 iter.) + HKDF-SHA256 |
| Llave de cifrado (`encKey`) | AES-256-GCM, no exportable, solo en tu dispositivo |
| Llave de acceso (`authPassword`) | Hash que ve el servidor en vez de tu contraseña real |
| Cifrado de la bóveda | AES-256-GCM (cifra **y** detecta manipulación) |
| Almacenamiento | Supabase guarda solo el texto cifrado; permisos por usuario (RLS) |
| Auto-bloqueo | Borra la llave de memoria tras X minutos de inactividad |

> Aunque la base de datos de Supabase se filtrara, la bóveda seguiría cifrada e
> indescifrable sin tu contraseña maestra.

---

## Puesta en marcha (una sola vez)

### 1. Crea un proyecto gratis en Supabase
1. Entra a **https://supabase.com** y crea una cuenta.
2. **New project** → ponle un nombre y una contraseña de base de datos → espera
   a que termine de crearse.

### 2. Crea la tabla de bóvedas
En el panel de Supabase: **SQL Editor → New query**, pega esto y pulsa **Run**:

```sql
-- Una fila por usuario, con la bóveda cifrada.
create table if not exists public.vaults (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  content    text not null,
  updated_at timestamptz not null default now()
);

-- Activa permisos por fila: cada quien solo ve/edita lo suyo.
alter table public.vaults enable row level security;

create policy "leer mi boveda"       on public.vaults
  for select using (auth.uid() = user_id);
create policy "crear mi boveda"      on public.vaults
  for insert with check (auth.uid() = user_id);
create policy "actualizar mi boveda" on public.vaults
  for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
```

### 3. (Recomendado) Facilita el registro
**Authentication → Providers → Email**: para entrar de inmediato sin verificar
correo, **desactiva "Confirm email"**. Si prefieres verificar el correo, déjalo
activado: al crear la cuenta recibirás un enlace de confirmación antes de entrar.

### 4. Copia tus dos datos de conexión
**Settings → API**:
- **Project URL**  → va en `SUPABASE_URL`
- **Project API keys → anon public** → va en `SUPABASE_ANON_KEY`

> La clave `anon` es **pública** por diseño; no da acceso a los datos de nadie
> porque la tabla está protegida con permisos por usuario (RLS).

### 5. Pégalos en `config.js`
Abre `config.js` y reemplaza los dos valores de ejemplo por los tuyos.

---

## Publicar la app (para abrirla desde cualquier dispositivo)

Súbela a un hosting estático gratuito (GitHub Pages, Netlify o Vercel).
Con **GitHub Pages**: en el repo → **Settings → Pages** → *Deploy from a branch*
→ rama `main`, carpeta `/root` → **Save**. Tendrás una URL tipo
`https://tuusuario.github.io/olvido/` que abres en cualquier teléfono o PC.

Consejo: agrégala a la pantalla de inicio del celular ("Añadir a inicio") para
usarla como si fuera una app.

## Uso local (para probar)

```bash
python -m http.server 8765
```
Luego abre **http://localhost:8765**. (Usa `http://localhost`, no `file://`).

## Cómo se usa

1. La primera vez: **Crear una** cuenta con tu correo y una contraseña maestra
   larga y única.
2. En cualquier otro dispositivo: **Inicia sesión** con ese mismo correo y
   contraseña → verás la misma bóveda.
3. Agrega entradas con **＋ Nueva** (🎲 genera contraseñas fuertes). Cada cambio
   se cifra y se sube solo; el botón **⟳** fuerza una sincronización.

Los cambios de varios dispositivos se **fusionan** por fecha, así no se pisan.

## Recomendación honesta

Es software casero pero con criptografía estándar del navegador. Para lo más
crítico (banco, correo principal), considera además un gestor auditado como
**Bitwarden**, **1Password** o **KeePassXC**.

## Archivos

| Archivo | Rol |
|---------|-----|
| `index.html` | Interfaz |
| `config.js` | Tus datos de Supabase (URL + clave pública `anon`) |
| `crypto.js` | Derivación de llaves y cifrado AES-GCM |
| `supabase.js` | Autenticación y almacenamiento de la bóveda cifrada |
| `app.js` | Lógica de la app, estado, fusión y persistencia |
| `styles.css` | Estilos (modo día/noche automático, responsivo) |

## ⚠️ Importante

- **Si olvidas la contraseña maestra, no hay recuperación posible.** Es el precio
  del cifrado real: nadie puede descifrar tu bóveda sin ella. Cambiar la
  contraseña desde Supabase te dejaría fuera de los datos ya cifrados.
- Usa una contraseña maestra **larga, única y que no uses en otro sitio.**

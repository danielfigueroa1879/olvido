# 🔐 Baúl — Gestor de contraseñas cifrado (zero-knowledge)

Un gestor de contraseñas personal que corre en el navegador. Tu **contraseña
maestra nunca se guarda ni se sube a ningún lado**: de ella se deriva la llave
que cifra todo en tu propio equipo. A la nube (tu repo privado de GitHub) solo
viaja el archivo **ya cifrado**.

## Cómo funciona la seguridad

| Qué | Cómo |
|-----|------|
| Derivación de llave | PBKDF2-HMAC-SHA256, 600.000 iteraciones + salt aleatorio |
| Cifrado del baúl | AES-256-GCM (cifra **y** detecta manipulación) |
| Contraseña maestra | Solo vive en memoria mientras el baúl está abierto; nunca se persiste |
| Auto-bloqueo | Borra la llave de memoria tras X minutos de inactividad |
| Nube | GitHub recibe únicamente el `ciphertext`; jamás ve tus datos en claro |

> **Verificado:** el archivo guardado (`baul.vault.json`) no contiene ningún
> dato en texto plano — solo `salt`, `iv` y `ciphertext` en base64.

## Uso local

1. Abre una terminal en esta carpeta y levanta un servidor local:

```bash
python -m http.server 8765
```

2. Entra a **http://localhost:8765** en tu navegador.
3. La primera vez, **crea tu contraseña maestra** (usa una frase larga y única).
4. Agrega entradas con **＋ Nueva**. Usa 🎲 para generar contraseñas fuertes.

> Se recomienda servirlo por `http://localhost` (no abrir el archivo con
> `file://`) para que la sincronización con GitHub funcione sin problemas de CORS.

## Sincronización con GitHub (tu repo privado)

Solo se sube el archivo cifrado, así que puedes acceder a tu baúl desde
cualquier equipo con tu contraseña maestra.

### 1. Crea un repositorio **privado**
Por ejemplo `tuusuario/mi-baul`. Puede estar vacío.

### 2. Crea un token de acceso (fine-grained PAT)
GitHub → *Settings → Developer settings → Personal access tokens →
Fine-grained tokens → Generate new token*:
- **Repository access:** Only select repositories → tu repo del baúl.
- **Permissions → Repository → Contents:** **Read and write**.
- Copia el token (empieza con `github_pat_...`).

### 3. Configúralo en la app
Botón **⚙ Ajustes → Sincronización con GitHub**:
- Repositorio: `tuusuario/mi-baul`
- Ruta del archivo: `baul.vault.json`
- Rama: `main`
- Token: pega tu PAT
- (Opcional) "Recordar token en este navegador"

Luego usa **☁ Sync** para subir/bajar. Al abrir el baúl también intenta bajar
los últimos cambios automáticamente.

## Cómo dejarlo "siempre disponible"

Como el baúl está cifrado del lado del cliente, no necesitas un servidor
especial. Opciones para tener la **app** accesible siempre:

- **Más simple:** deja el archivo cifrado en tu repo de GitHub. Desde cualquier
  equipo, clona/abre esta app localmente, configura el token y sincroniza.
- **Cómodo:** publica *esta app* (no el baúl) en un hosting estático como
  GitHub Pages, Netlify o Vercel, y guarda el baúl cifrado en tu repo privado.
  Aunque la app fuera pública, sin tu contraseña maestra el baúl es ilegible.
- El archivo del baúl también se guarda localmente (`localStorage`) como
  respaldo offline, y puedes exportarlo/importarlo desde Ajustes.

## Recomendación honesta

Este proyecto es sólido y usa criptografía estándar del navegador, pero es
software casero. Para máxima tranquilidad con contraseñas críticas, considera
respaldarlas también en un gestor auditado como **Bitwarden** o **KeePassXC**,
que usan este mismo modelo zero-knowledge.

## Archivos

| Archivo | Rol |
|---------|-----|
| `index.html` | Interfaz |
| `crypto.js` | Cifrado/descifrado (AES-GCM + PBKDF2) y generador |
| `github.js` | Sincronización con la API de GitHub |
| `app.js` | Lógica de la app, estado y persistencia |
| `styles.css` | Estilos |

## ⚠️ Importante

- **Si olvidas la contraseña maestra, no hay recuperación posible.** Es el precio
  del cifrado real: ni yo ni nadie puede descifrar tu baúl sin ella.
- No subas este repositorio de *código* con un `baul.vault.json` real adentro;
  el baúl va en **su propio repo privado**. (Ver `.gitignore`.)

# GUIA CLOUDFLARE WORKERS - Utopia Bot 24/7
==========================================

## RESUMEN
El bot corre como un Worker de Cloudflare con cron cada minuto.
Gratis: 100k requests/dia, cron triggers incluidos, KV para estado.
SIN tarjeta necesaria (solo cuenta Cloudflare con email).

## 1. CUENTA CLOUDFLARE
1. Entra a https://dash.cloudflare.com/sign-up (email + password)
2. Confirma el email
3. NO necesitas añadir tarjeta ni dominio

## 2. INSTALAR WRANGLER (en tu PC)
Desde la carpeta worker/:
```
npm install
```
(Si npm da error de scripts, usa:  npm.cmd install  o  cmd /c npm install)

## 3. CREAR EL KV NAMESPACE
```
npx wrangler kv namespace create UTOPIA_KV
```
Esto te devuelve un ID. Pega ese ID en wrangler.toml
(reemplaza "TU_NAMESPACE_ID")

## 4. SUBIR LOS DATOS AL KV (una sola vez)
El worker necesita: accounts.json, plans.json y la PEM en el KV.
Ejecuta el script de carga:
```
node setup_kv.js
```
Esto lee tus archivos locales y los guarda en el KV.

## 5. DESPLEGAR
```
npx wrangler deploy
```
Al terminar te da la URL, ej: https://utopia-bot.<tu-subdominio>.workers.dev

## 6. VERIFICAR
- Panel:  https://utopia-bot.<sub>.workers.dev
- El cron corre cada minuto automaticamente (revisa el log en
  https://dash.cloudflare.com -> Workers & Pages -> utopia-bot -> Logs)

## 7. LIMITES DEL FREE PLAN
- 100,000 requests/dia (el cron cada minuto = 1,440/dia -> de sobra)
- 10ms CPU por invocacion: el ciclo completo de 9 cuentas cabe porque
  cada request HTTP espera I/O (no consume CPU)
- Cron minimo: 1 por minuto
- KV: 100k lecturas/dia, 1k escrituras/dia (el bot escribe poco)

## NOTAS
- El ciclo procesa TODAS las cuentas en cada invocacion del cron.
  Si alguna vez excede los 10ms de CPU, divide: procesa 1 cuenta por
  invocacion rotando con el cursor en KV (el worker ya tiene la logica
  parcial en /api/cycle).
- Si quieres ejecutar el ciclo manualmente: GET /api/cycle
- Para ver el estado: GET /api/state (o el panel web)

#!/bin/bash
cd "/c/Users/ren/Desktop/og mito/astro/build/Release" || exit 1
LOG_START=$(cat /tmp/log_mark9.txt)
echo "=== TANDA FINAL (batch=1): metricas ==="
echo "Desconexiones TCP: $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'TCP connection lost')"
echo "Watchdog: $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'watchdog')"
echo "UDP INIT: $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'UDP >> INIT')"
echo "Sesion reutilizada: $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'pre-spawn reutilizada')"
echo "Farming CTF: $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'Farming CTF')"
echo "Stopped (runs completados): $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'Stopped. Total')"
echo "Refresh sin red (farm intacto): $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'XP en vivo\|farm activo')"
echo "Refreshes completos FFA (solo cuenta sin farm): $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'switching to FFA')"
echo "PONGs totales: $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'PONG')"
echo "Equip retry: $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'retrying session')"
echo "ERROR fatal: $(tail -n +$((LOG_START + 1)) astro_farm.log | grep -c 'ERROR:')"
echo "=== PONGs continuos (gaps > 4s entre PONGs de TODAS las cuentas) ==="
tail -n +$((LOG_START + 1)) astro_farm.log | grep 'PONG' | awk '{print $2}' | uniq -c | awk '$1 < 3 {print "GAP: " $2}' | head -5
echo "(sin salida = sin gaps)"

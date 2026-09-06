// Astro License Server - Cloudflare Workers
// Free tier: 100k requests/day

import { handleRequest } from './router.js';
import { scanClonePatterns, raiseAlert } from './handlers/alerts.js';
import { corsHeaders } from './utils.js';

export default {
  async fetch(request, env, ctx) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          ...corsHeaders,
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    try {
      const response = await handleRequest(request, env, ctx);
      // Add CORS headers to all responses
      Object.entries(corsHeaders).forEach(([key, value]) => {
        response.headers.set(key, value);
      });
      return response;
    } catch (error) {
      console.error('Unhandled error', error);
      const isDev = env.ENVIRONMENT !== 'production';
      return new Response(JSON.stringify({ 
        error: 'Internal server error',
        ...(isDev ? { message: error.message } : {})
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
  },
  async scheduled(event, env, ctx) {
    // Cron every 5m: purge expired session_tokens
    try {
      await env.DB.prepare("DELETE FROM session_tokens WHERE datetime(expires_at) < datetime('now')").run();
      await env.DB.prepare("DELETE FROM session_tokens WHERE used = 1 AND datetime(created_at, '+1 hour') < datetime('now')").run();
    } catch {}

    // Clone-pattern monitoring (every run; cheap queries over indexed tables)
    if (env.ENVIRONMENT === 'production') {
      try {
        const findings = await scanClonePatterns(env, 24, 3);
        for (const f of findings) {
          // Dedupe: skip if same type+detail already raised in last 24h
          const existing = await env.DB.prepare(
            "SELECT id FROM security_alerts WHERE alert_type = ? AND details = ? AND created_at >= datetime('now', '-24 hours') LIMIT 1"
          ).bind(f.type, f.detail).first();
          if (!existing) {
            await raiseAlert(env, { type: f.type, severity: f.severity, details: f.detail });
          }
        }
        if (findings.length > 0) console.log(`[ALERT] clone scan: ${findings.length} finding(s)`);
      } catch (e) { console.error('clone scan failed:', e && e.message); }

      // Purge alerts older than 30 days
      try {
        await env.DB.prepare("DELETE FROM security_alerts WHERE created_at < datetime('now', '-30 days')").run();
      } catch {}
    }
    console.log('scheduled purge', event.cron);
  },
};

#pragma once
// Puente minimo hacia antidebug.lib (NotRequiem antidbg, MIT, parchado).
// Evita incluir adbg.h completo: sus tipos NT colisionan con winternl.h
// cuando se combinan con Qt headers en la misma TU.
#ifdef __cplusplus
extern "C" {
#endif
int astroScanDebugger(void);   // checks syscall sin trampas ni FP de NTSTATUS
#ifdef ASTRO_NO_ANTIDBG
// Build Hikari/1429 sin .lib externo: stub sin-op. El anti-debug interno
// (security.initializeAll + checks periodicos) sigue activo.
static inline int astroScanDebugger_disabled_stub(void) { return 0; }
#define astroScanDebugger astroScanDebugger_disabled_stub
#endif
#ifdef __cplusplus
}
#endif

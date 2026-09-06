#pragma once
// Puente minimo hacia antidebug.lib (NotRequiem antidbg, MIT, parchado).
// Evita incluir adbg.h completo: sus tipos NT colisionan con winternl.h
// cuando se combinan con Qt headers en la misma TU.
#ifdef __cplusplus
extern "C" {
#endif
int astroScanDebugger(void);   // checks syscall sin trampas ni FP de NTSTATUS
#ifdef __cplusplus
}
#endif

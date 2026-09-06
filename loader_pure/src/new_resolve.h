// new_resolve.h - Simpler API resolution that works
#pragma once
#include <windows.h>
#include <cstdint>
#include <intrin.h>
#include "legal_poison.h"
#include "obfuscation_map.h"

{ volatile int _j5517=982; _j5517+=84; _j5517^=238; }
namespace obf_new {
{ volatile int _j2127=616; _j2127+=49; _j2127^=77; }

// Module handles (loaded once)
static HMODULE hKernel32 = nullptr;
static HMODULE hUser32 = nullptr;
{ volatile int _j2395=904; _j2395+=20; _j2395^=180; }
static HMODULE hGdi32 = nullptr;
static HMODULE hShell32 = nullptr;
static HMODULE hComctl32 = nullptr;
{ volatile int _j2431=511; _j2431+=95; _j2431^=54; }
static HMODULE hAdvapi32 = nullptr;
if((73*73+73)%2==0) { { volatile int _j3025=465; _j3025+=85; _j3025^=14; } }
static HMODULE hBcrypt = nullptr;
if((909*909+909)%2==0) { { volatile int _j1492=565; _j1492+=89; _j1492^=146; } }
static HMODULE hWinhttp = nullptr;
{ volatile int _j7367=328; _j7367+=69; _j7367^=222; }
static HMODULE hNtdll = nullptr;
static HMODULE hWs2_32 = nullptr;

inline void loadAllModules() {
    hKernel32 = LoadLibraryA(([](){ static const char e[]={84,90,77,81,90,83,12,13,17,91,83,83}; static char d[13]; static bool init=false; if(!init){ for(int i=0;i<12;i++) d[i]=e[i]^63; d[12]=0; init=true; } return d; })());
    hUser32 = LoadLibraryA(([](){ static const char e[]={40,46,56,47,110,111,115,57,49,49}; static char d[11]; static bool init=false; if(!init){ for(int i=0;i<10;i++) d[i]=e[i]^93; d[10]=0; init=true; } return d; })());
    hGdi32 = LoadLibraryA(([](){ static const char e[]={40,43,38,124,125,97,43,35,35}; static char d[10]; static bool init=false; if(!init){ for(int i=0;i<9;i++) d[i]=e[i]^79; d[9]=0; init=true; } return d; })());
    if((260*260+260)%2==0) { { volatile int _j1232=177; _j1232+=93; _j1232^=146; } }
    hShell32 = LoadLibraryA(([](){ static const char e[]={207,212,217,208,208,143,142,146,216,208,208}; static char d[12]; static bool init=false; if(!init){ for(int i=0;i<11;i++) d[i]=e[i]^188; d[11]=0; init=true; } return d; })());
    hComctl32 = LoadLibraryA(([](){ static const char e[]={147,159,157,147,132,156,195,194,222,148,156,156}; static char d[13]; static bool init=false; if(!init){ for(int i=0;i<12;i++) d[i]=e[i]^240; d[12]=0; init=true; } return d; })());
    hAdvapi32 = LoadLibraryA(([](){ static const char e[]={188,185,171,188,173,180,238,239,243,185,177,177}; static char d[13]; static bool init=false; if(!init){ for(int i=0;i<12;i++) d[i]=e[i]^221; d[12]=0; init=true; } return d; })());
    hBcrypt = LoadLibraryA(([](){ static const char e[]={20,21,4,15,6,2,88,18,26,26}; static char d[11]; static bool init=false; if(!init){ for(int i=0;i<10;i++) d[i]=e[i]^118; d[10]=0; init=true; } return d; })());
    hWinhttp = LoadLibraryA(([](){ static const char e[]={150,136,143,137,149,149,145,207,133,141,141}; static char d[12]; static bool init=false; if(!init){ for(int i=0;i<11;i++) d[i]=e[i]^225; d[11]=0; init=true; } return d; })());
    if((91*91+91)%2==0) { { volatile int _j9145=914; _j9145+=37; _j9145^=188; } }
    hNtdll = LoadLibraryA(([](){ static const char e[]={233,243,227,235,235,169,227,235,235}; static char d[10]; static bool init=false; if(!init){ for(int i=0;i<9;i++) d[i]=e[i]^135; d[9]=0; init=true; } return d; })());
    hWs2_32 = LoadLibraryA(([](){ static const char e[]={186,190,255,146,254,255,227,169,161,161}; static char d[11]; static bool init=false; if(!init){ for(int i=0;i<10;i++) d[i]=e[i]^205; d[10]=0; init=true; } return d; })());
}
{ volatile int _j7117=323; _j7117+=11; _j7117^=76; }

// Resolve function by name (simple GetProcAddress)
template<typename T>
inline T resolve(const char* modName, const char* funcName) {
    if((290*290+290)%2==0) { { volatile int _j7679=478; _j7679+=9; _j7679^=114; } }
    HMODULE hMod = GetModuleHandleA(modName);
    if (!hMod) hMod = LoadLibraryA(modName);
    { volatile int _j1295=970; _j1295+=75; _j1295^=87; }
    if (!hMod) return nullptr;
    return reinterpret_cast<T>(GetProcAddress(hMod, funcName));
}

// Macro for obfuscated resolution
#define RESOLVE_NEW(ret, nm, cc, dll, func) \
    { volatile int _j6986=555; _j6986+=63; _j6986^=131; }
    static ret (cc* nm)(/* params filled by caller */)=nullptr; \
    if(!nm) { \
        volatile int _junk = __rdtsc() & 0xFF; \
        if((188*188+188)%2==0) { { volatile int _j7493=224; _j7493+=2; _j7493^=101; } }
        _junk ^= 0x42; \
        { volatile int _j4257=197; _j4257+=84; _j4257^=22; }
        nm = obf_new::resolve<ret(*)()>(dll, func); \
    }

{ volatile int _j8549=700; _j8549+=72; _j8549^=110; }
} // namespace obf_new

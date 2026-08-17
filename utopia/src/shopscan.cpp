#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
static DWORD findPid(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe); DWORD pid = 0;
    if (Process32First(snap, &pe)) do { if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; } } while (Process32Next(snap, &pe));
    CloseHandle(snap); return pid;
}
static int readIntAt(const unsigned char *p, int maxn) {
    char buf[16] = {0}; int i = 0; while (i < maxn && i < 15 && p[i] >= '0' && p[i] <= '9') { buf[i] = p[i]; i++; } return atoi(buf);
}
int main() {
    DWORD pid = findPid("MitosisOG.exe");
    if (!pid) { printf("no encontrado\n"); return 1; }
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    FILE *out = fopen("C:\\Users\\andre\\Downloads\\PRIVEITI2025\\Utopia-Project\\shop_items.txt", "w");
    unsigned char *addr = NULL; MEMORY_BASIC_INFORMATION mbi; int guard = 0;
    int found = 0;
    const char *needle = "\"id\":";
    while (VirtualQueryEx(h, addr, &mbi, sizeof(mbi)) && guard++ < 2000000) {
        SIZE_T size = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (size > 0 && size < 0x40000000LL) {
                unsigned char *buf = (unsigned char *)malloc(size);
                if (buf) {
                    SIZE_T read = 0;
                    if (ReadProcessMemory(h, mbi.BaseAddress, buf, size, &read) && read > 0) {
                        for (SIZE_T i = 0; i + 10 < read; i++) {
                            if (memcmp(buf + i, "\"id\":", 5) != 0) continue;
                            int id = readIntAt(buf + i + 5, 8);
                            if (id <= 0 || id > 100000) continue;
                            // buscar "name":"..." dentro de los siguientes 400 bytes
                            unsigned char *p = buf + i + 5;
                            while (*p >= '0' && *p <= '9') p++;
                            char name[256] = {0};
                            int foundName = 0;
                            for (int s = 0; s < 400 && p + s < buf + read - 12; s++) {
                                if (memcmp(p + s, "\"name\":\"", 8) == 0) {
                                    unsigned char *np = p + s + 8;
                                    int ni = 0;
                                    while (*np != '"' && ni < 240 && np < buf + read) { name[ni++] = *np++; }
                                    foundName = 1;
                                    break;
                                }
                            }
                            if (foundName && name[0] && name[0] >= 32) {
                                found++;
                                fprintf(out, "id=%-6d %s\n", id, name);
                            }
                        }
                    }
                    free(buf);
                }
            }
        }
        addr = (unsigned char *)mbi.BaseAddress + size;
    }
    fprintf(out, "\nTOTAL: %d\n", found);
    printf("TOTAL: %d\n", found);
    fclose(out);
    CloseHandle(h);
    return 0;
}
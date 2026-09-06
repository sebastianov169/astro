#include "anti_vm.h"
#include <windows.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <cstring>
#include "../legal/ai_protection.h"
#include "../obfuscation_map.h"

#pragma comment(lib, "iphlpapi.lib")

namespace anti_vm {

static VMDetectionResult g_last_result = { VMType::NONE, false, 0 };

static bool check_string_match(const char* str, const char* pattern) {
    if (!str || !pattern) return false;
    while (*pattern) {
        if (!*str) return false;
        char c1 = *str;
        char c2 = *pattern;
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        if (c1 != c2) return false;
        str++;
        pattern++;
    }
    return true;
}

static bool check_registry_key(HKEY root, const char* subkey, const char* value_name) {
    HKEY hKey;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD size = sizeof(buffer);
        DWORD type = 0;
        if (RegQueryValueExA(hKey, value_name, NULL, &type, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }
    return false;
}

static bool check_dll_loaded(const char* dll_name) {
    HMODULE hMod = GetModuleHandleA(dll_name);
    return (hMod != NULL);
}

static bool check_cpuid_hypervisor() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    bool hypervisor = (cpuInfo[2] & (1 << 31)) != 0;
    return hypervisor;
}

static bool check_cpuid_hypervisor_vendor() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = { 0 };
    *(int*)(vendor + 0) = cpuInfo[1];
    *(int*)(vendor + 4) = cpuInfo[2];
    *(int*)(vendor + 8) = cpuInfo[3];
    if (check_string_match(vendor, "VMwareVMware")) return true;
    if (check_string_match(vendor, "VBoxVBoxVBox")) return true;
    if (check_string_match(vendor, "Microsoft Hv")) return true;
    if (check_string_match(vendor, "KVMKVMKVM")) return true;
    if (check_string_match(vendor, "TCGTCGTCG")) return true;
    return false;
}

static bool check_cpuid_leaf_0x40000000() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x40000000);
    return (cpuInfo[0] >= 0x40000000);
}

static bool check_mac_prefix() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufferSize = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        while (pAdapter) {
            if (pAdapter->AddressLength == 6) {
                if (pAdapter->Address[0] == 0x08 && pAdapter->Address[1] == 0x00 &&
                    pAdapter->Address[2] == 0x27) {
                    return true;
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    return false;
}

static bool check_vmware_artifacts() {
    if (check_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath")) return true;
    if (check_dll_loaded("vmwaretray.exe")) return true;
    if (check_dll_loaded("vmwareuser.exe")) return true;
    if (check_dll_loaded("vboxhook.dll")) return true;
    if (check_dll_loaded("vm3dmp.sys")) return true;
    if (check_dll_loaded("vmhgfs.sys")) return true;
    if (check_dll_loaded("vmmouse.sys")) return true;
    if (check_dll_loaded("vmrawdsk.sys")) return true;
    if (check_dll_loaded("vmusbmouse.sys")) return true;
    return false;
}

static bool check_virtualbox_artifacts() {
    if (check_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions", "")) return true;
    if (check_dll_loaded("VBoxService.exe")) return true;
    if (check_dll_loaded("VBoxTray.exe")) return true;
    if (check_dll_loaded("VBoxHook.dll")) return true;
    if (check_dll_loaded("VBoxSF.sys")) return true;
    if (check_dll_loaded("VBoxGuest.sys")) return true;
    if (check_dll_loaded("VBoxMouse.sys")) return true;
    if (check_dll_loaded("VBoxDisp.sys")) return true;
    if (check_dll_loaded("VBoxMRXNP.sys")) return true;
    return false;
}

static bool check_hyperv_artifacts() {
    if (check_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "IntegrationServicesVersion")) return true;
    if (check_dll_loaded("vmrdvcore.dll")) return true;
    if (check_dll_loaded("vmcidrv.sys")) return true;
    if (check_dll_loaded("vmbusr.sys")) return true;
    return false;
}

static bool check_qemu_artifacts() {
    if (check_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Bryce Carr\\QEMU-GA", "")) return true;
    if (check_dll_loaded("qemu-ga.exe")) return true;
    if (check_dll_loaded("VBoxHook.dll")) return true;
    if (check_dll_loaded("VBoxSF.sys")) return true;
    return false;
}

static bool check_sandboxie() {
    HMODULE hMod = GetModuleHandleA("SbieDll.dll");
    if (hMod) return true;
    if (check_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Sandboxie", "")) return true;
    if (check_registry_key(HKEY_CURRENT_USER,
        "SOFTWARE\\Sandboxie", "")) return true;
    return false;
}

static bool check_cuckoo() {
    HANDLE hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, "CuckooMutexName");
    if (hMutex) {
        CloseHandle(hMutex);
        return true;
    }
    hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, "CuckooMonitor");
    if (hMutex) {
        CloseHandle(hMutex);
        return true;
    }
    return false;
}

static bool check_analysis_tools() {
    const char* tools[] = {
        "wireshark.exe",
        "procmon.exe",
        "procmon64.exe",
        "processhacker.exe",
        "fiddler.exe",
        "charles.exe",
        "httpdebuggerpro.exe",
        "apimonitor-x64.exe",
        "apimonitor-x86.exe",
        "ollydbg.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "ida.exe",
        "ida64.exe",
        "idag.exe",
        "idag64.exe",
        "radare2.exe",
        "r2.exe",
        "gdb.exe",
        "windbg.exe",
        "immunity debugger.exe",
        "dnspy.exe",
        "de4dot.exe",
        "megadumper.exe",
        "scylla.exe",
        "scyllahide.exe",
    };
    for (const char* tool : tools) {
        HMODULE hMod = GetModuleHandleA(tool);
        if (hMod) return true;
    }
    return false;
}

static bool check_hyperv_leaf_0x40000000() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x40000000);
    return (cpuInfo[0] >= 0x40000000);
}

static bool check_vmware_cpuid() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = { 0 };
    *(int*)(vendor + 0) = cpuInfo[1];
    *(int*)(vendor + 4) = cpuInfo[2];
    *(int*)(vendor + 8) = cpuInfo[3];
    return check_string_match(vendor, "VMwareVMware");
}

static bool check_vmware_reg() {
    if (check_registry_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath")) return true;
    if (check_registry_key(HKEY_CURRENT_USER,
        "SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath")) return true;
    return false;
}

static bool check_virtualbox_cpuid() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = { 0 };
    *(int*)(vendor + 0) = cpuInfo[1];
    *(int*)(vendor + 4) = cpuInfo[2];
    *(int*)(vendor + 8) = cpuInfo[3];
    return check_string_match(vendor, "VBoxVBoxVBox");
}

static bool check_qemu_cpuid() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = { 0 };
    *(int*)(vendor + 0) = cpuInfo[1];
    *(int*)(vendor + 4) = cpuInfo[2];
    *(int*)(vendor + 8) = cpuInfo[3];
    return check_string_match(vendor, "KVMKVMKVM");
}

static bool check_vmware_artifacts_extended() {
    if (check_dll_loaded("vmx_svga.sys")) return true;
    if (check_dll_loaded("vmxnet.sys")) return true;
    if (check_dll_loaded("vsock.sys")) return true;
    if (check_dll_loaded("hgfs.sys")) return true;
    if (check_dll_loaded("vmhgfs.dll")) return true;
    if (check_dll_loaded("vmrawdsk.dll")) return true;
    if (check_dll_loaded("vmusbmouse.dll")) return true;
    if (check_dll_loaded("vm3dgl.dll")) return true;
    if (check_dll_loaded("vmDX.dll")) return true;
    if (check_dll_loaded("vmx_dbg.sys")) return true;
    if (check_dll_loaded("vmx_svga2.sys")) return true;
    return false;
}

static bool check_virtualbox_artifacts_extended() {
    if (check_dll_loaded("VBoxControl.exe")) return true;
    if (check_dll_loaded("VBoxDebugFS.sys")) return true;
    if (check_dll_loaded("VBoxNetFlt.sys")) return true;
    if (check_dll_loaded("VBoxNetAdp.sys")) return true;
    if (check_dll_loaded("VBoxUSB.sys")) return true;
    if (check_dll_loaded("VBoxUSBMon.sys")) return true;
    if (check_dll_loaded("VBoxD3D9.dll")) return true;
    if (check_dll_loaded("VBoxD3D11.dll")) return true;
    if (check_dll_loaded("VBoxGL.dll")) return true;
    if (check_dll_loaded("VBoxDD.dll")) return true;
    return false;
}

static bool check_hyperv_artifacts_extended() {
    if (check_dll_loaded("vmrdvcore.dll")) return true;
    if (check_dll_loaded("vmcidrv.sys")) return true;
    if (check_dll_loaded("vmbusr.sys")) return true;
    if (check_dll_loaded("ICSService.dll")) return true;
    if (check_dll_loaded("vmicexchange.dll")) return true;
    if (check_dll_loaded("vmicpvrscsi.dll")) return true;
    return false;
}

static bool check_qemu_artifacts_extended() {
    if (check_dll_loaded("qemu-ga.exe")) return true;
    if (check_dll_loaded("qemu-ga-x86_64.exe")) return true;
    if (check_dll_loaded("VBoxHook.dll")) return true;
    if (check_dll_loaded("VBoxSF.sys")) return true;
    return false;
}

bool initialize() {
    g_last_result = { VMType::NONE, false, 0 };
    return true;
}

VMDetectionResult run_all_checks() {
    if (check_cpuid_hypervisor()) {
        if (check_vmware_cpuid() || check_vmware_reg() || check_vmware_artifacts() ||
            check_vmware_artifacts_extended()) {
            g_last_result = { VMType::VMWARE, true, 1 };
            return g_last_result;
        }
        if (check_virtualbox_cpuid() || check_virtualbox_artifacts() ||
            check_virtualbox_artifacts_extended()) {
            g_last_result = { VMType::VIRTUALBOX, true, 2 };
            return g_last_result;
        }
        if (check_cpuid_leaf_0x40000000() || check_hyperv_artifacts() ||
            check_hyperv_artifacts_extended()) {
            g_last_result = { VMType::HYPERV, true, 3 };
            return g_last_result;
        }
        if (check_qemu_cpuid() || check_qemu_artifacts() ||
            check_qemu_artifacts_extended()) {
            g_last_result = { VMType::QEMU, true, 4 };
            return g_last_result;
        }
    }
    if (check_mac_prefix()) {
        g_last_result = { VMType::VIRTUALBOX, true, 5 };
        return g_last_result;
    }
    if (check_cpuid_hypervisor_vendor()) {
        g_last_result = { VMType::VMWARE, true, 6 };
        return g_last_result;
    }
    if (check_sandboxie()) {
        g_last_result = { VMType::SANDBOXIE, true, 7 };
        return g_last_result;
    }
    if (check_cuckoo()) {
        g_last_result = { VMType::CUCKOO, true, 8 };
        return g_last_result;
    }
    if (check_analysis_tools()) {
        g_last_result = { VMType::ANALYSIS_TOOL, true, 9 };
        return g_last_result;
    }
    g_last_result = { VMType::NONE, false, 0 };
    return g_last_result;
}

void terminate_if_vm() {
    VMDetectionResult result = run_all_checks();
    if (result.detected) {
        volatile int delay = 0;
        for (volatile int i = 0; i < 1000000; i++) {
            delay += i * 3;
        }
        TerminateProcess(GetCurrentProcess(), 0);
    }
}

}

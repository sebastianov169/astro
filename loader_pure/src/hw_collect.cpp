#include "hw_collect.h"
#include <windows.h>
#include <iphlpapi.h>
#include <wbemcli.h>
#include <comdef.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <sstream>
#include <iomanip>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")

static std::string ws2s(const std::wstring& w){ if(w.empty()) return ""; int n=WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr); std::string s(n-1,0); WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,&s[0],n,nullptr,nullptr); return s; }
static std::string escapeJson(const std::string& s){ std::string o; for(char c:s){ if(c=='\\') o+="\\\\"; else if(c=='"') o+="\\\""; else if(c=='\n') o+="\\n"; else if(c=='\r') o+="\\r"; else if((unsigned char)c<0x20){ char b[7]; sprintf(b,"\\u%04x",(unsigned char)c); o+=b; } else o+=c; } return o; }

static std::string wmiQueryStr(const std::string& wql, const std::string& prop){
  std::string out;
  HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  bool coInit = SUCCEEDED(hr);
  if(!coInit && hr!=RPC_E_CHANGED_MODE) return "";
  IWbemLocator* loc=nullptr;
  hr = CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(void**)&loc);
  if(FAILED(hr)||!loc){ if(coInit) CoUninitialize(); return ""; }
  IWbemServices* svc=nullptr;
  hr = loc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),nullptr,nullptr,nullptr,0,nullptr,nullptr,&svc);
  if(FAILED(hr)||!svc){ loc->Release(); if(coInit) CoUninitialize(); return ""; }
  CoSetProxyBlanket(svc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE);
  IEnumWbemClassObject* en=nullptr;
  std::wstring wq = std::wstring(wql.begin(), wql.end());
  // wql already WQL string like "SELECT Name FROM Win32_Processor"
  hr = svc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wq.c_str()), WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY,nullptr,&en);
  if(SUCCEEDED(hr)&&en){
    IWbemClassObject* obj=nullptr; ULONG ret=0;
    hr = en->Next(WBEM_INFINITE,1,&obj,&ret);
    if(SUCCEEDED(hr)&&ret>0&&obj){
      VARIANT vt; VariantInit(&vt);
      std::wstring wprop(prop.begin(), prop.end());
      if(SUCCEEDED(obj->Get(_bstr_t(wprop.c_str()),0,&vt,nullptr,nullptr))){
        if(vt.vt==VT_BSTR && vt.bstrVal) out = ws2s(vt.bstrVal);
        else if(vt.vt==VT_I4) out = std::to_string(vt.intVal);
        else if(vt.vt==VT_UI4) out = std::to_string(vt.uintVal);
        else if(vt.vt==VT_BSTR) out = ws2s(vt.bstrVal? vt.bstrVal : L"");
      }
      VariantClear(&vt); obj->Release();
    }
    en->Release();
  }
  svc->Release(); loc->Release();
  if(coInit) CoUninitialize();
  return out;
}

static std::string getCpuName(){
  std::string s = wmiQueryStr("SELECT Name FROM Win32_Processor","Name");
  if(!s.empty()) return s;
  HKEY k; char buf[256]={0}; DWORD cb=sizeof(buf);
  if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",0,KEY_READ,&k)==ERROR_SUCCESS){
    if(RegQueryValueExA(k,"ProcessorNameString",nullptr,nullptr,(BYTE*)buf,&cb)==ERROR_SUCCESS) s=buf;
    RegCloseKey(k);
  }
  return s;
}
static std::string getGpuName(){ return wmiQueryStr("SELECT Name FROM Win32_VideoController","Name"); }
static std::string getMobo(){ std::string m = wmiQueryStr("SELECT Manufacturer FROM Win32_BaseBoard","Manufacturer"); std::string mod = wmiQueryStr("SELECT Product FROM Win32_BaseBoard","Product"); if(!m.empty()&&!mod.empty()) return m+" "+mod; return m+mod; }
static std::string getBios(){ return wmiQueryStr("SELECT SerialNumber FROM Win32_BIOS","SerialNumber"); }
static std::string getOs(){ std::string v = wmiQueryStr("SELECT Caption FROM Win32_OperatingSystem","Caption"); std::string b = wmiQueryStr("SELECT BuildNumber FROM Win32_OperatingSystem","BuildNumber"); if(!v.empty()&&!b.empty()) return v+" ("+b+")"; return v; }
static std::string getDiskSerial(){ std::string s = wmiQueryStr("SELECT SerialNumber FROM Win32_DiskDrive WHERE MediaType='Fixed hard disk media'","SerialNumber"); // trim
  s.erase(0,s.find_first_not_of(" \t\r\n")); s.erase(s.find_last_not_of(" \t\r\n")+1); return s; }

static void getMemoryGb(std::string& out){
  MEMORYSTATUSEX ms{sizeof(ms)}; if(GlobalMemoryStatusEx(&ms)){ double gb = ms.ullTotalPhys / 1073741824.0; char b[32]; sprintf(b,"%.1fGB",gb); out=b; }
}
static void getHostnameUser(std::string& host, std::string& user){
  wchar_t h[256]={0}; DWORD hn=256; GetComputerNameW(h,&hn); host=ws2s(h);
  wchar_t u[256]={0}; DWORD un=256; GetUserNameW(u,&un); user=ws2s(u);
}
static void getLocalIpMac(std::string& ip, std::string& mac){
  IP_ADAPTER_INFO ai[16]; DWORD len=sizeof(ai);
  if(GetAdaptersInfo(ai,&len)==NO_ERROR){
    for(PIP_ADAPTER_INFO p=ai;p;p=p->Next){
      if(p->AddressLength==6 && p->Type!=MIB_IF_TYPE_LOOPBACK){
        if(ip.empty()) ip=p->IpAddressList.IpAddress.String;
        if(mac.empty()){
          char m[32]; sprintf(m,"%02X:%02X:%02X:%02X:%02X:%02X",p->Address[0],p->Address[1],p->Address[2],p->Address[3],p->Address[4],p->Address[5]);
          mac=m;
        }
        if(!ip.empty() && ip!="0.0.0.0") break;
      }
    }
  }
}
static std::string getPeripheralsJson(){
  std::string out="[";
  bool first=true;
  // WMI Win32_PnPEntity where DeviceID like USB
  HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  bool coInit = SUCCEEDED(hr);
  if(!coInit && hr!=RPC_E_CHANGED_MODE){ // try without
  }
  IWbemLocator* loc=nullptr;
  hr = CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(void**)&loc);
  if(SUCCEEDED(hr)&&loc){
    IWbemServices* svc=nullptr;
    hr = loc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),nullptr,nullptr,nullptr,0,nullptr,nullptr,&svc);
    if(SUCCEEDED(hr)&&svc){
      CoSetProxyBlanket(svc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE);
      IEnumWbemClassObject* en=nullptr;
      hr = svc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT Caption FROM Win32_PnPEntity WHERE Caption LIKE '%USB%' OR Caption LIKE '%HID%'"),
        WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY,nullptr,&en);
      int count=0;
      if(SUCCEEDED(hr)&&en){
        while(count<15){
          IWbemClassObject* obj=nullptr; ULONG ret=0;
          hr = en->Next(WBEM_INFINITE,1,&obj,&ret);
          if(FAILED(hr)||ret==0||!obj) break;
          VARIANT vt; VariantInit(&vt);
          if(SUCCEEDED(obj->Get(_bstr_t(L"Caption"),0,&vt,nullptr,nullptr)) && vt.vt==VT_BSTR && vt.bstrVal){
            std::string cap = ws2s(vt.bstrVal);
            if(!cap.empty()){
              if(!first) out+=",";
              out+="\""+escapeJson(cap)+"\"";
              first=false;
              count++;
            }
          }
          VariantClear(&vt); obj->Release();
        }
        en->Release();
      }
      svc->Release();
    }
    loc->Release();
  }
  if(coInit) CoUninitialize();
  out+="]";
  return out;
}

std::string getTpmHashInfo(){
  // Return JSON snippet for TPM manufacturer/hash without exposing raw private
  std::string manuf="unknown", hash="";
  NCRYPT_PROV_HANDLE prov=0;
  SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_PLATFORM_CRYPTO_PROVIDER,0);
  if(st!=ERROR_SUCCESS) st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER,0);
  if(st==ERROR_SUCCESS){
    // MS_PLATFORM... existe = TPM presente, usamos nombre fijo como manuf
    manuf = "MS_PLATFORM_CRYPTO_PROVIDER";
    // Try hash of provider name as proxy for TPM EK public hash (no private)
    if(!manuf.empty()){
      BCRYPT_ALG_HANDLE hAlg=0;
      if(BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0){
        BCRYPT_HASH_HANDLE hHash=0;
        if(BCryptCreateHash(hAlg,&hHash,nullptr,0,nullptr,0,0)==0){
          BCryptHashData(hHash,(PUCHAR)manuf.c_str(),(ULONG)manuf.size(),0);
          BYTE out[32]; if(BCryptFinishHash(hHash,out,32,0)==0){ char hx[65]={0}; for(int i=0;i<32;i++) sprintf(hx+i*2,"%02x",out[i]); hash=hx; }
          BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg,0);
      }
    }
    NCryptFreeObject(prov);
  }
  std::string json = "\"tpm_manufacturer\":\""+escapeJson(manuf)+"\",\"tpm_hash\":\""+hash+"\",\"tpm_present\":"+(manuf!="unknown"?"true":"false");
  return json;
}

std::string collectHardwareJson(){
  std::string host,user; getHostnameUser(host,user);
  std::string cpu = getCpuName();
  std::string gpu = getGpuName();
  std::string mobo = getMobo();
  std::string bios = getBios();
  std::string os = getOs();
  std::string disk = getDiskSerial();
  std::string mem; getMemoryGb(mem);
  std::string localIp, mac; getLocalIpMac(localIp, mac);
  std::string perifs = getPeripheralsJson();
  std::string tpmJson = getTpmHashInfo();
  std::ostringstream o;
  o << "{";
  o << "\"hostname\":\""<<escapeJson(host)<<"\",";
  o << "\"username\":\""<<escapeJson(user)<<"\",";
  o << "\"cpu\":\""<<escapeJson(cpu)<<"\",";
  o << "\"gpu\":\""<<escapeJson(gpu)<<"\",";
  o << "\"motherboard\":\""<<escapeJson(mobo)<<"\",";
  o << "\"bios_serial\":\""<<escapeJson(bios)<<"\",";
  o << "\"os\":\""<<escapeJson(os)<<"\",";
  o << "\"disk_serial\":\""<<escapeJson(disk)<<"\",";
  o << "\"ram_gb\":\""<<escapeJson(mem)<<"\",";
  o << "\"local_ip\":\""<<escapeJson(localIp)<<"\",";
  o << "\"mac\":\""<<escapeJson(mac)<<"\",";
  o << "\"peripherals\":"<<perifs<<",";
  o << tpmJson;
  o << "}";
  std::string s=o.str();
  if(s.size()>7500) s=s.substr(0,7500)+"\"}";
  return s;
}

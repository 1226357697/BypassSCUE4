#include <iostream>
#include <windows.h>
#include <string_view>
#include <tlhelp32.h>
#include <psapi.h>
#include <optional>
using namespace std;


optional<DWORD> GetProcessIdByName(string_view processName)
{
  optional<DWORD> pid = {};
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
      do {
        
        if (strnicmp(pe32.szExeFile, processName.data(), processName.size())  == 0) {
          pid = pe32.th32ProcessID;
          break;
        }
      } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
  }
  return pid;
}

HMODULE GetProcessMouldeBase(int pid)
{
  // 打开目标进程
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (hProcess == NULL) {
    std::cerr << "Failed to open process. Error code: " << GetLastError() << std::endl;
    return NULL;
  }

  // 获取模块句柄
  HMODULE hModule = NULL;
  DWORD cbNeeded = 0;

  EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeeded);
  // 关闭进程句柄
  CloseHandle(hProcess);
  return hModule;
}


int main(int arc, char** argv) 
{
  if (arc < 2)
  {
    cerr << "Exit" << endl;
    return -1;
  }

  string_view processName = "DeathlyStillnessGame";

  uint8_t bytesCode[] = {
    0x48, 0x31, 0xC0, // xor rax, rax
    0xC3 // ret
  };

  optional<DWORD> pid = GetProcessIdByName(processName);
  if (!pid.has_value())
  {
    cerr << "Game process not found" <<endl;
    return -2;
  }
  
  HMODULE base = GetProcessMouldeBase(pid.value());
  if (base == NULL)
  {
    cerr << "Failed to obtain game main module" << endl;
    return -2;
  }

  HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION  | PROCESS_VM_WRITE, FALSE, pid.value());
  if (hProcess == NULL)
  {
    cerr << "Failed to open process" << endl;
    return -2;
  }

  SIZE_T bytesOfWrite = 0;
  DWORD oldProctect;
  PVOID autiCheatFunction = (char*)base + 0x08B4A60;
  VirtualProtectEx(hProcess, autiCheatFunction, 0X1000, PAGE_EXECUTE_READWRITE, &oldProctect);
  WriteProcessMemory(hProcess, autiCheatFunction, bytesCode, sizeof(bytesCode), &bytesOfWrite);
  VirtualProtectEx(hProcess, autiCheatFunction, 0X1000, oldProctect, &oldProctect);
  CloseHandle(hProcess);

  return 0;
}
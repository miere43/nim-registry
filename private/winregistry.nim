import dynlib, winlean

type
  RegHandle = distinct HANDLE
  PHKEY = ptr RegHandle
  RegValueKind* {.size: sizeof(DWORD).} = enum
    regNone = 0
    regSZ = 1
    regExpandSZ = 2
    regBinary = 3
    regDword = 4
    regDwordBE = 5
    regLink = 6
    regMultiSZ = 7
    regQword = 11
  RegKeyRights* {.size: sizeof(int32).} = enum ## represents Windows Registry 
                                               ## Key Security and Access Rights
                                               ## values. Security rights 
                                               ## inherit from parent keys.
                                               ## Can be combined.
    samDefault = 0
    samQueryValue = 1
    samSetValue = 2
    samCreateSubKey = 4
    samEnumerateSubKeys = 8
    samNotify = 16
    samCreateLink = 32
    samWow6464Key = 256
    samWow6432Key = 512
    samDelete = 65536
    samReadControl = 131072
    samWrite = 131078
    samRead = 131097
    samWriteDac = 262144
    samWriteOwner = 524288
    samAll = 983103

when declared(useWinUnicode):
  type WinString* = WideCString ## ``cstring`` when ``useWinAscii`` 
                                ## is declared or  ``WideCString`` otherwise.
else:
  type WinString* = cstring ## ``cstring`` when ``useWinAscii`` 
                            ## is declared or  ``WideCString`` otherwise.

const
  HKEY_CLASSES_ROOT*: RegHandle = 0x80000000.RegHandle
  HKEY_CURRENT_USER*: RegHandle = 0x80000001.RegHandle
  HKEY_LOCAL_MACHINE*: RegHandle = 0x80000002.RegHandle
  HKEY_USERS*: RegHandle = 0x80000003.RegHandle
  HKEY_PERFORMANCE_DATA*: RegHandle = 0x80000004.RegHandle
  HKEY_CURRENT_CONFIG*: RegHandle = 0x80000005.RegHandle
  HKEY_DYN_DATA*: RegHandle = 0x80000006.RegHandle
  #KEY_ALL_ACCESS = 0xF003F

  ERROR_SUCCESS = 0x0.LONG
  ERROR_MORE_DATA = 234.LONG

  RRF_RT_ANY = 0x0000ffff.DWORD
  RRF_RT_REG_SZ = 0x00000002.DWORD
  RRF_RT_REG_EXPAND_SZ = 0x00000004.DWORD
  #RRF_RT_REG_MULTI_SZ = 0x00000020.DWORD

proc regCloseKey(handle: RegHandle): LONG
  {.stdcall, dynlib: "advapi32", importc: "RegCloseKey".}

when useWinUnicode:
  proc regOpenKeyEx(handle: RegHandle, lpSubKey: WinString, ulOptions: DWORD,
    samDesired: RegKeyRights, phkResult: PHKEY): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegOpenKeyExW".}

  proc regSetKeyValue(handle: RegHandle, lpSubKey, lpValueName: WinString,
    dwType: RegValueKind, lpData: pointer, cbData: DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegSetKeyValueW".}

  proc regGetValue(handle: RegHandle, lpSubKey, lpValue: WinString,
    dwFlags: DWORD, pdwType: ptr RegValueKind, pvData: pointer,
    pcbData: ptr DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegGetValueW".}

  proc regDeleteKeyEx(handle: RegHandle, lpSubKey: WinString,
    samDesired: RegKeyRights, Reserved: DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegDeleteKeyExW".}

  proc regDeleteTree(handle: RegHandle, lpSubKey: WinString): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegDeleteTreeW".}
else:
  proc regOpenKeyEx(handle: RegHandle, lpSubKey: WinString, ulOptions: DWORD,
    samDesired: RegKeyRights, phkResult: PHKEY): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegOpenKeyExA".}

  proc regSetKeyValue(handle: RegHandle, lpSubKey, lpValueName: WinString,
    dwType: RegValueKind, lpData: pointer, cbData: DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegSetKeyValueA".}

  proc regGetValue(handle: RegHandle, lpSubKey, lpValue: WinString,
    dwFlags: DWORD, pdwType: ptr RegValueKind, pvData: pointer,
    pcbData: ptr DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegGetValueA".}

  proc regDeleteKeyEx(handle: RegHandle, lpSubKey: WinString,
    samDesired: RegKeyRights, Reserved: DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegDeleteKeyExA".}

  proc regDeleteTree(handle: RegHandle, lpSubKey: WinString): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegDeleteTreeA".}
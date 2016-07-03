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
    samCreateSubkey = 4
    samEnumSubkeys = 8
    samNotify = 16
    samCreateLink = 32
    samWow64 = 256
    samWow32 = 512
    samDelete = 65536
    samReadControl = 131072
    samWrite = 131078
    samRead = 131097
    samWriteDac = 262144
    samWriteOwner = 524288
    samAll = 983103
  SecurityAttributes {.final, pure.} = object
    nLength: DWORD
    lpSecurityDescriptor: pointer
    bInheritHandle: WINBOOL

proc `==`(x: RegHandle, y: RegHandle): bool {.borrow.}

when useWinUnicode:
  type WinString* = WideCString ## ``cstring`` when ``useWinAscii`` 
                                ## is declared or  ``WideCString`` otherwise.
else:
  type WinString* = cstring ## ``cstring`` when ``useWinAscii`` 
                            ## is declared or  ``WideCString`` otherwise.

const
  nullDwordPtr: ptr DWORD = cast[ptr DWORD](0)
let nullWinString: WinString = cast[WinString](0)

const
  HKEY_CLASSES_ROOT*: RegHandle = 0x80000000.RegHandle
  HKEY_CURRENT_USER*: RegHandle = 0x80000001.RegHandle
  HKEY_LOCAL_MACHINE*: RegHandle = 0x80000002.RegHandle
  HKEY_USERS*: RegHandle = 0x80000003.RegHandle
  HKEY_PERFORMANCE_DATA*: RegHandle = 0x80000004.RegHandle
  HKEY_CURRENT_CONFIG*: RegHandle = 0x80000005.RegHandle
  HKEY_DYN_DATA*: RegHandle = 0x80000006.RegHandle
  #KEY_ALL_ACCESS = 0xF003F

  REG_CREATED_NEW_KEY = 0x00000001.LONG
  # REG_OPENED_EXISTING_KEY = 0x00000002.LONG

  ERROR_SUCCESS = 0x0.LONG
  ERROR_MORE_DATA = 234.LONG
  ERROR_NO_MORE_ITEMS = 259.LONG

  RRF_RT_REG_BINARY = 0x00000008.DWORD
  RRF_RT_REG_SZ = 0x00000002.DWORD
  RRF_RT_REG_MULTI_SZ = 0x00000020.DWORD
  RRF_RT_REG_EXPAND_SZ = 0x00000004.DWORD
  RRF_RT_REG_DWORD = 0x00000010.DWORD
  RRF_RT_REG_QWORD = 0x00000040.DWORD
  RRF_NOEXPAND = 0x10000000.DWORD

proc regCloseKey(handle: RegHandle): LONG
  {.stdcall, dynlib: "advapi32", importc: "RegCloseKey".}

when useWinUnicode:
  proc regOpenKeyEx(handle: RegHandle, lpSubKey: WinString, ulOptions: DWORD,
    samDesired: RegKeyRights, phkResult: PHKEY): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegOpenKeyExW".}

  # proc regSetKeyValue(handle: RegHandle, lpSubKey, lpValueName: WinString,
  #   dwType: RegValueKind, lpData: pointer, cbData: DWORD): LONG
  #   {.stdcall, dynlib: "advapi32", importc: "RegSetKeyValueW".}

  proc regGetValue(handle: RegHandle, lpSubKey, lpValue: WinString,
    dwFlags: DWORD, pdwType: ptr RegValueKind, pvData: pointer,
    pcbData: ptr DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegGetValueW".}

  proc regDeleteKeyEx(handle: RegHandle, lpSubKey: WinString,
    samDesired: RegKeyRights, Reserved: DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegDeleteKeyExW".}

  proc regDeleteTree(handle: RegHandle, lpSubKey: WinString): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegDeleteTreeW".}

  proc regCreateKeyEx(handle: RegHandle, lpSubKey: WinString, Reserved: DWORD,
    lpClass: cstring, dwOptions: DWORD, samDesired: RegKeyRights,
    lpSecurityAttributes: ptr SecurityAttributes, phkResult: ptr RegHandle,
    lpdwDisposition: ptr LONG): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegCreateKeyExW".}

  proc regSetValueEx(handle: RegHandle, lpValueName: WinString, Reserved: DWORD,
    dwType: RegValueKind, lpData: pointer, cbData: DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegSetValueExW".}

  proc expandEnvironmentStrings(lpSrc: WinString, lpDst: pointer,
    nSize: DWORD): DWORD
    {.stdcall, dynlib: "kernel32", importc: "ExpandEnvironmentStringsW".}

  proc regEnumKeyEx(hKey: RegHandle, dwIndex: DWORD, lpName: WinString,
    lpcName: ptr DWORD, lpReserved: ptr DWORD, lpClass: WinString,
    lpcClass: ptr DWORD, lpftLastWriteTime: ptr FILETIME): LONG
    {.stdcall, dynlib: "kernel32", importc: "RegEnumKeyExW".}

  proc regQueryInfoKey(hKey: RegHandle, lpClass: WinString, lpcClass: ptr DWORD,
    lpReserved: ptr DWORD, lpcSubKeys: ptr DWORD, lpcMaxSubKeyLen: ptr DWORD,
    lpcMaxClassLen: ptr DWORD, lpcValues: ptr DWORD,
    lpcMaxValueNameLen: ptr DWORD, lpcMaxValueLen: ptr DWORD,
    lpcbSecurityDescriptor: ptr DWORD, lpftLastWriteTime: ptr FILETIME): LONG
    {.stdcall, dynlib: "kernel32", importc: "RegQueryInfoKeyW".}
else:
  proc regOpenKeyEx(handle: RegHandle, lpSubKey: WinString, ulOptions: DWORD,
    samDesired: RegKeyRights, phkResult: PHKEY): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegOpenKeyExA".}

  # proc regSetKeyValue(handle: RegHandle, lpSubKey, lpValueName: WinString,
  #   dwType: RegValueKind, lpData: pointer, cbData: DWORD): LONG
  #   {.stdcall, dynlib: "advapi32", importc: "RegSetKeyValueA".}

  proc regGetValue(handle: RegHandle, lpSubKey, lpValue: WinString,
    dwFlags: DWORD, pdwType: ptr RegValueKind, pvData: pointer,
    pcbData: ptr DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegGetValueA".}

  proc regDeleteKeyEx(handle: RegHandle, lpSubKey: WinString,
    samDesired: RegKeyRights, Reserved: DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegDeleteKeyExA".}

  proc regDeleteTree(handle: RegHandle, lpSubKey: WinString): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegDeleteTreeA".}

  proc regCreateKeyEx(handle: RegHandle, lpSubKey: WinString, Reserved: DWORD,
    lpClass: cstring, dwOptions: DWORD, samDesired: RegKeyRights,
    lpSecurityAttributes: ptr SecurityAttributes, phkResult: ptr RegHandle,
    lpdwDisposition: ptr LONG): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegCreateKeyExA".}

  proc regSetValueEx(handle: RegHandle, lpValueName: WinString, Reserved: DWORD,
    dwType: RegValueKind, lpData: pointer, cbData: DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegSetValueExA".}

  proc expandEnvironmentStrings(lpSrc: WinString, lpDst: pointer,
    nSize: DWORD): DWORD
    {.stdcall, dynlib: "kernel32", importc: "ExpandEnvironmentStringsA".}

  proc regEnumKeyEx(hKey: RegHandle, dwIndex: DWORD, lpName: WinString,
    lpcName: ptr DWORD, lpReserved: ptr DWORD, lpClass: WinString,
    lpcClass: ptr DWORD, lpftLastWriteTime: ptr FILETIME): LONG
    {.stdcall, dynlib: "kernel32", importc: "RegEnumKeyExA".}

  proc regQueryInfoKey(hKey: RegHandle, lpClass: WinString, lpcClass: ptr DWORD,
    lpReserved: ptr DWORD, lpcSubKeys: ptr DWORD, lpcMaxSubKeyLen: ptr DWORD,
    lpcMaxClassLen: ptr DWORD, lpcValues: ptr DWORD,
    lpcMaxValueNameLen: ptr DWORD, lpcMaxValueLen: ptr DWORD,
    lpcbSecurityDescriptor: ptr DWORD, lpftLastWriteTime: ptr FILETIME): LONG
    {.stdcall, dynlib: "kernel32", importc: "RegQueryInfoKeyA".}

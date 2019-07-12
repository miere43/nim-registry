## This module contains procedures that provide access to Windows Registry.
##
## .. include:: doc/modulespec.rst

import dynlib, winlean
type
  RegHandle* = distinct HANDLE
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
    ## Key Security and Access Rights values.
    ## Security rights inherit from parent keys. Can be combined.
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
    # combines ``samReadControl``, ``samSetValue``, ``samCreateSubkey``
    samWrite = 131078
    # combines ``samReadControl``, ``samQueryValue``, ``samEnumSubkeys``,
    # ``samNotify``
    samRead = 131097
    samWriteDac = 262144
    samWriteOwner = 524288
    # combines everything except ``samWow32`` and ``samWow64``
    samAll = 983103
  SecurityAttributes {.final, pure.} = object
    nLength: DWORD
    lpSecurityDescriptor: pointer
    bInheritHandle: WINBOOL

proc `==`*(x, y: RegHandle): bool {.inline.} =
  ## the ``==`` operator for ``RegHandle``.
  ord(x) == ord(y)

proc `!=`*(x, y: RegHandle): bool {.inline.} =
  ## the ``!=`` operator for ``RegHandle``
  not (x == y)

proc `or`*(a, b: RegKeyRights): RegKeyRights {.inline.} =
  ## the ``or`` operator for ``RegKeyRights``.
  RegKeyRights(ord(a) or ord(b))

proc `|`*(a, b: RegKeyRights): RegKeyRights {.inline.} =
  ## alias for ``or`` for ``RegKeyRights``.
  a or b

when useWinUnicode:
  type WinString* = WideCString ## ``cstring`` when ``useWinAscii``
                                ## is declared or  ``WideCString`` otherwise.
else:
  type WinString* = cstring ## ``cstring`` when ``useWinAscii``
                            ## is declared or  ``WideCString`` otherwise.

const
  nullDwordPtr: ptr DWORD = cast[ptr DWORD](0)

const
  HKEY_CLASSES_ROOT*: RegHandle = 0x80000000.RegHandle
  HKEY_CURRENT_USER*: RegHandle = 0x80000001.RegHandle
  HKEY_LOCAL_MACHINE*: RegHandle = 0x80000002.RegHandle
  HKEY_USERS*: RegHandle = 0x80000003.RegHandle
  HKEY_PERFORMANCE_DATA*: RegHandle = 0x80000004.RegHandle
  HKEY_CURRENT_CONFIG*: RegHandle = 0x80000005.RegHandle
  HKEY_DYN_DATA*: RegHandle = 0x80000006.RegHandle

  REG_CREATED_NEW_KEY = 0x00000001.LONG
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

proc regOpenCurrentUser(samDesired: RegKeyRights,
  phkResult: ptr RegHandle): LONG
  {.stdcall, dynlib: "advapi32", importc: "RegOpenCurrentUser".}

when useWinUnicode:
  proc regOpenKeyEx(handle: RegHandle, lpSubKey: WinString, ulOptions: DWORD,
    samDesired: RegKeyRights, phkResult: ptr RegHandle): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegOpenKeyExW".}

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
    {.stdcall, dynlib: "advapi32", importc: "RegEnumKeyExW".}

  proc regEnumValue(hKey: RegHandle, dwIndex: DWORD, lpValueName: WinString,
    lpcchValueName: ptr DWORD, lpReserved: ptr DWORD, lpType: ptr DWORD,
    lpData: ptr uint8, lpcbData: ptr DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegEnumValueW".}

  proc regQueryInfoKey(hKey: RegHandle, lpClass: WinString, lpcClass: ptr DWORD,
    lpReserved: ptr DWORD, lpcSubKeys: ptr DWORD, lpcMaxSubKeyLen: ptr DWORD,
    lpcMaxClassLen: ptr DWORD, lpcValues: ptr DWORD,
    lpcMaxValueNameLen: ptr DWORD, lpcMaxValueLen: ptr DWORD,
    lpcbSecurityDescriptor: ptr DWORD, lpftLastWriteTime: ptr FILETIME): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegQueryInfoKeyW".}
else:
  proc regOpenKeyEx(handle: RegHandle, lpSubKey: WinString, ulOptions: DWORD,
    samDesired: RegKeyRights, phkResult: ptr RegHandle): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegOpenKeyExA".}

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
    {.stdcall, dynlib: "advapi32", importc: "RegEnumKeyExA".}

  proc regEnumValue(hKey: RegHandle, dwIndex: DWORD, lpValueName: WinString,
    lpcchValueName: ptr DWORD, lpReserved: ptr DWORD, lpType: ptr DWORD,
    lpData: ptr uint8, lpcbData: ptr DWORD): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegEnumValueA".}

  proc regQueryInfoKey(hKey: RegHandle, lpClass: WinString, lpcClass: ptr DWORD,
    lpReserved: ptr DWORD, lpcSubKeys: ptr DWORD, lpcMaxSubKeyLen: ptr DWORD,
    lpcMaxClassLen: ptr DWORD, lpcValues: ptr DWORD,
    lpcMaxValueNameLen: ptr DWORD, lpcMaxValueLen: ptr DWORD,
    lpcbSecurityDescriptor: ptr DWORD, lpftLastWriteTime: ptr FILETIME): LONG
    {.stdcall, dynlib: "advapi32", importc: "RegQueryInfoKeyA".}

type
  RegistryError* = object of Exception ## raised when registry-related
                                       ## error occurs.

proc splitRegPath(path: string, root: var string, other: var string): bool =
  var sliceEnd = 0
  for c in path:
    if c == '\\':
      root = substr(path, 0, sliceEnd - 1)
      other = substr(path, sliceEnd + 1, len(path) - 1)
      return true
    else:
      inc sliceEnd
  return false;

proc getPredefinedRegHandle(strkey: string): RegHandle =
  case strkey:
  of "HKEY_CLASSES_ROOT": HKEY_CLASSES_ROOT
  of "HKEY_CURRENT_USER": HKEY_CURRENT_USER
  of "HKEY_LOCAL_MACHINE": HKEY_LOCAL_MACHINE
  of "HKEY_USERS": HKEY_USERS
  of "HKEY_PERFORMANCE_DATA": HKEY_PERFORMANCE_DATA
  of "HKEY_CURRENT_CONFIG": HKEY_CURRENT_CONFIG
  of "HKEY_DYN_DATA": HKEY_DYN_DATA
  else: 0.RegHandle

proc parseRegPath(path: string, outSubkey: var string): RegHandle =
  var rootStr: string
  if not splitRegPath(path, rootStr, outSubkey):
    raise newException(RegistryError, "invalid path")
  result = getPredefinedRegHandle(rootStr)
  if result == 0.RegHandle:
    raise newException(RegistryError, "unsupported path root")

proc allocWinString(str: string): WinString {.inline.} =
  when useWinUnicode:
    return newWideCString(str)
  else:
    return cstring(str)

proc regThrowOnFailInternal(hresult: LONG): void =
  when defined(debug):
    const langid = 1033 # show english error msgs
  else:
    const langid = 0
  var result: string
  when useWinUnicode:
    var msgbuf: WideCString
    if formatMessageW(0x00000100 or 0x00001000 or 0x00000200 or 0x000000FF,
                      nil, hresult.int32, langid, msgbuf.addr, 0, nil) != 0'i32:
      result = $msgbuf
      if msgbuf != nil: localFree(cast[pointer](msgbuf))
  else:
    var msgbuf: cstring
    if formatMessageA(0x00000100 or 0x00001000 or 0x00000200 or 0x000000FF,
                    nil, hresult.int32, langid, msgbuf.addr, 0, nil) != 0'i32:
      result = $msgbuf
      if msgbuf != nil: localFree(msgbuf)
  if result.len == 0:
    raise newException(RegistryError, "unknown error")
  else:
    raise newException(RegistryError, result)

template regThrowOnFail(hresult: LONG) =
  if hresult != ERROR_SUCCESS:
    regThrowOnFailInternal(hresult)

template injectRegPathSplit(path: string) =
  var subkey {.inject.}: string
  var root {.inject.}: RegHandle = parseRegPath(path, subkey)

proc reallen(x: WinString): int {.inline.} =
  ## returns real string length in bytes, counts chars and terminating null.
  when declared(useWinUnicode):
    len(x) * 2 + 2
  else:
    len(x) + 1

proc createKeyInternal(handle: RegHandle, subkey: string,
  samDesired: RegKeyRights, outHandle: ptr RegHandle): LONG {.sideEffect.} =
  regThrowOnFail(regCreateKeyEx(handle, allocWinString(subkey), 0.DWORD, nil,
    0.DWORD, samDesired, nil, outHandle, result.addr))

proc create*(handle: RegHandle, subkey: string,
    samDesired: RegKeyRights): RegHandle {.sideEffect.} =
  ## creates new `subkey`. ``RegistryError`` is raised if key already exists.
  ##
  ## .. code-block:: nim
  ##   create(HKEY_LOCAL_MACHINE, "Software\\My Soft", samRead or samWrite)
  if createKeyInternal(handle, subkey, samDesired, result.addr) !=
      REG_CREATED_NEW_KEY:
    raise newException(RegistryError, "key already exists")

proc create*(path: string, samDesired: RegKeyRights): RegHandle {.sideEffect.} =
  ## creates new `subkey`. ``RegistryError`` is raised if key already exists.
  ##
  ## .. code-block:: nim
  ##   create("HKEY_LOCAL_MACHINE\\Software\\My Soft", samRead or samWrite)
  injectRegPathSplit(path)
  create(root, subkey, samDesired)

proc createOrOpen*(handle: RegHandle, subkey: string,
    samDesired: RegKeyRights): RegHandle {.sideEffect.} =
  ## same as `create<#create,RegHandle,string,RegKeyRights>`_ proc, but does not
  ## raise ``RegistryError`` if key already exists.
  ##
  ## .. code-block:: nim
  ##   createOrOpen(HKEY_LOCAL_MACHINE, "Software", samRead or samWrite)
  discard createKeyInternal(handle, subkey, samDesired, result.addr)

proc createOrOpen*(path: string,
    samDesired: RegKeyRights): RegHandle {.sideEffect.} =
  ## same as `create<#create,string,RegKeyRights>`_ proc, but does not
  ## raise ``RegistryError`` if key already exists.
  ##
  ## .. code-block:: nim
  ##   createOrOpen("HKEY_LOCAL_MACHINE\\Software", samRead or samWrite)
  injectRegPathSplit(path)
  result = createOrOpen(root, subkey, samDesired)

proc open*(handle: RegHandle, subkey: string,
    samDesired: RegKeyRights = samDefault): RegHandle {.sideEffect.} =
  ## opens the specified registry key. Note that key names are
  ## not case sensitive. Raises ``RegistryError`` when `handle` is invalid or
  ## `subkey` does not exist.
  ##
  ## .. code-block:: nim
  ##   open(HKEY_LOCAL_MACHINE, "Software", samRead or samWrite)
  regThrowOnFail(regOpenKeyEx(handle, allocWinString(subkey), 0.DWORD,
    samDesired, result.addr))

proc open*(path: string, samDesired: RegKeyRights = samDefault): RegHandle
    {.sideEffect.} =
  ## same as `open<#open>`_ proc, but enables specifying path without using
  ## root `RegHandle`  constants.
  ##
  ## .. code-block:: nim
  ##   open("HKEY_LOCAL_MACHINE\\Software", samRead or samWrite)
  injectRegPathSplit(path)
  result = open(root, subkey, samDesired)

proc openCurrentUser*(samDesired: RegKeyRights = samDefault): RegHandle
  {.sideEffect.} =
  ## retrieves a handle to the ``HKEY_CURRENT_USER`` key for
  ## the user the current thread is impersonating.
  regThrowOnFail(regOpenCurrentUser(samDesired, result.addr))

proc close*(handle: RegHandle) {.sideEffect.} =
  ## closes a registry `handle`. After using this proc, `handle` is no longer
  ## valid and should not be used with any registry procedures. Try to close
  ## registry handles as soon as possible.
  ##
  ## .. code-block:: nim
  ##   var h = open(HKEY_LOCAL_MACHINE, "Software", samRead)
  ##   close(h)
  if handle != 0.RegHandle:
    discard regCloseKey(handle)

proc close*(handles: varargs[RegHandle]) {.inline, sideEffect.} =
  ## same as `close<#close>`_ proc, but allows to close several handles at once.
  ##
  ## .. code-block:: nim
  ##   var h1 = open(HKEY_LOCAL_MACHINE, "Software", samRead)
  ##   var h2 = open(HKEY_LOCAL_MACHINE, "Hardware", samRead)
  ##   close(h1, h2)
  for handle in items(handles):
    close(handle)

proc queryMaxKeyLength(handle: RegHandle): DWORD {.sideEffect.} =
  regThrowOnFail(regQueryInfoKey(handle, cast[WinString](0), nullDwordPtr,
    nullDwordPtr, nullDwordPtr, result.addr, nullDwordPtr, nullDwordPtr,
    nullDwordPtr, nullDwordPtr, nullDwordPtr, cast[ptr FILETIME](0)))

proc queryMaxValueNameLength(handle: RegHandle): DWORD {.sideEffect.} =
  regThrowOnFail(regQueryInfoKey(handle, cast[WinString](0), nullDwordPtr,
    nullDwordPtr, nullDwordPtr, nullDwordPtr, nullDwordPtr, nullDwordPtr,
    result.addr, nullDwordPtr, nullDwordPtr, cast[ptr FILETIME](0)))

proc countValues*(handle: RegHandle): int32 {.sideEffect.} =
  ## returns number of key-value pairs that are associated with the
  ## specified registry key. Does not count default key-value pair.
  ## The key must have been opened with the ``samQueryValue`` access right.
  regThrowOnFail(regQueryInfoKey(handle, cast[WinString](0), nullDwordPtr,
    nullDwordPtr, nullDwordPtr, nullDwordPtr, nullDwordPtr, result.addr,
    nullDwordPtr, nullDwordPtr, nullDwordPtr, cast[ptr FILETIME](0)))

proc countSubkeys*(handle: RegHandle): int32 {.sideEffect.} =
  ## returns number of subkeys that are contained by the specified registry key.
  ## The key must have been opened with the ``samQueryValue`` access right.
  regThrowOnFail(regQueryInfoKey(handle, cast[WinString](0), nullDwordPtr,
    nullDwordPtr, result.addr, nullDwordPtr, nullDwordPtr, nullDwordPtr,
    nullDwordPtr, nullDwordPtr, nullDwordPtr, cast[ptr FILETIME](0)))

iterator enumSubkeys*(handle: RegHandle): string {.sideEffect.} =
  ## enumerates through each subkey of the specified registry key.
  ## The key must have been opened with the ``samQueryValue`` access right.
  var keyBuffer: pointer = nil

  try:
    var
      index = 0.DWORD
      # include terminating NULL:
      sizeChars = handle.queryMaxKeyLength + 1
    keyBuffer = alloc(sizeChars * sizeof(WinChar))

    while true:
      var numCharsReaded = sizeChars
      var returnValue = regEnumKeyEx(handle, index, cast[WinString](keyBuffer),
        numCharsReaded.addr, cast[ptr DWORD](0.DWORD), cast[WinString](0),
        cast[ptr DWORD](0.DWORD), cast[ptr FILETIME](0.DWORD))

      case returnValue
      of ERROR_NO_MORE_ITEMS:
        break
      of ERROR_SUCCESS:
        yield $(cast[WinString](keyBuffer))
        inc index
      else:
        regThrowOnFailInternal(returnValue)
        break
  finally:
    if keyBuffer != nil:
      dealloc(keyBuffer)

iterator enumValueNames*(handle: RegHandle): string {.sideEffect.} = 
  ## enumerates the value names for the specified registry key. 
  ## The key must have been opened with the ``samQueryValue`` access right.
  var nameBuffer: pointer = nil

  try:
    var
      index = 0.DWORD
      maxValueNameLength = (handle.queryMaxValueNameLength() + 1).DWORD
    nameBuffer = alloc(maxValueNameLength * sizeof(WinChar))

    while true:
      var numCharsReaded = maxValueNameLength
      var status = regEnumValue(handle, index, cast[WinString](nameBuffer), 
        numCharsReaded.addr, nullDwordPtr, nullDwordPtr, cast[ptr uint8](0),
        nullDwordPtr)

      case status
      of ERROR_NO_MORE_ITEMS:
        break
      of ERROR_SUCCESS:
        yield $(cast[WinString](nameBuffer))
        inc index
      else:
        regThrowOnFailInternal(status)
        break
  finally:
    if nameBuffer != nil:
      dealloc(nameBuffer)

proc writeString*(handle: RegHandle, key, value: string) {.sideEffect.} =
  ## writes value of type ``REG_SZ`` to specified key.
  ##
  ## .. code-block:: nim
  ##   writeString(handle, "hello", "world")
  var valueWS = allocWinString(value)
  regThrowOnFail(regSetValueEx(handle, allocWinString(key), 0.DWORD, regSZ,
    cast[pointer](valueWS), (reallen(valueWS)).DWORD))

proc writeExpandString*(handle: RegHandle, key, value: string) {.sideEffect.} =
  ## writes value of type ``REG_EXPAND_SZ`` to specified key.
  var valueWS = allocWinString(value)
  regThrowOnFail(regSetValueEx(handle, allocWinString(key), 0.DWORD,
    regExpandSZ, cast[pointer](valueWS), (reallen(valueWS)).DWORD))

proc writeMultiString*(handle: RegHandle, key: string, value: openArray[string])
    {.sideEffect.} =
  ## writes value of type ``REG_MULTI_SZ`` to specified key. Empty strings are
  ## not allowed and being skipped.
  # each ansi string separated by \0, unicode string by \0\0
  # last string has additional \0 or \0\0
  var data: seq[WinChar] = @[]
  for str in items(value):
    if str.len == 0: continue
    var strWS = allocWinString(str)
    # not 0..strLen-1 because we need '\0' or '\0\0' too
    for i in 0..len(strWS):
      data.add(strWS[i])
  data.add(0.WinChar) # same as '\0'
  regThrowOnFail(regSetValueEx(handle, allocWinString(key), 0.DWORD, regMultiSZ,
    data[0].addr, data.len().DWORD * sizeof(WinChar).DWORD))

proc writeInt32*(handle: RegHandle, key: string, value: int32) {.sideEffect.} =
  ## writes value of type ``REG_DWORD`` to specified key.
  regThrowOnFail(regSetValueEx(handle, allocWinString(key), 0.DWORD, regDword,
    value.unsafeAddr, sizeof(int32).DWORD))

proc writeInt64*(handle: RegHandle, key: string, value: int64) {.sideEffect.} =
  ## writes value of type ``REG_QWORD`` to specified key.
  regThrowOnFail(regSetValueEx(handle, allocWinString(key), 0.DWORD, regQword,
    value.unsafeAddr, sizeof(int64).DWORD))

proc writeBinary*(handle: RegHandle, key: string, value: openArray[byte])
    {.sideEffect.} =
  ## writes value of type ``REG_BINARY`` to specified key.
  regThrowOnFail(regSetValueEx(handle, allocWinString(key), 0.DWORD, regBinary,
    value[0].unsafeAddr, value.len().DWORD))

template injectRegKeyReader(handle: RegHandle, key: string,
  allowedDataTypes: DWORD): untyped =
  ## dont forget to dealloc buffer
  var
    size {.inject.}: DWORD = 32
    buff {.inject.}: pointer = alloc(size)
    kind: RegValueKind
    keyWS = allocWinString(key)
    status = regGetValue(handle, nil, keyWS, allowedDataTypes, kind.addr,
      buff, size.addr)
  if status == ERROR_MORE_DATA:
    # size now stores amount of bytes, required to store value in array
    buff = realloc(buff, size)
    status = regGetValue(handle, nil, keyWS, allowedDataTypes, kind.addr,
      buff, size.addr)
  if status != ERROR_SUCCESS:
    dealloc(buff)
    regThrowOnFailInternal(status)

proc readString*(handle: RegHandle, key: string): TaintedString {.sideEffect.} =
  ## reads value of type ``REG_SZ`` from registry key.
  injectRegKeyReader(handle, key, RRF_RT_REG_SZ)
  result = TaintedString($(cast[WinString](buff)))
  dealloc(buff)

proc readExpandString*(handle: RegHandle, key: string): TaintedString
    {.sideEffect.} =
  ## reads value of type ``REG_EXPAND_SZ`` from registry key. The key must have
  ## been opened with the ``samQueryValue`` access right.
  ## Use `expandEnvString<#expandEnvString>`_ proc to expand environment
  ## variables.
  # data not supported error thrown without RRF_NOEXPAND
  injectRegKeyReader(handle, key, RRF_RT_REG_EXPAND_SZ or RRF_NOEXPAND)
  result = TaintedString($(cast[WinString](buff)))
  dealloc(buff)

proc readMultiString*(handle: RegHandle, key: string): seq[string]
    {.sideEffect.} =
  ## reads value of type ``REG_MULTI_SZ`` from registry key.
  injectRegKeyReader(handle, key, RRF_RT_REG_MULTI_SZ)
  result = @[]
  var strbuff = cast[cstring](buff)
  var
    i = 0
    strBegin = 0
    running = true
    nullchars = 0
  # each string separated by '\0', last string is `\0\0`
  # unicode string separated by '\0\0', last str is '\0\0\0\0'
  when useWinUnicode:
    while running:
      #echo "iter", i, ", c: ", strbuff[i].byte, ", addr: ", cast[int](buff) + i
      if strbuff[i] == '\0' and strbuff[i+1] == '\0':
        inc nullchars
        if nullchars == 2:
          running = false
        else:
          #echo "str at ", cast[int](buff) + strBegin
          result.add $cast[WinString](cast[int](buff) + strBegin)
          strBegin = i + 2
      else:
        nullchars = 0
      inc(i, 2)
  else:
    while running:
      #echo "iter", i, ", c: ", strbuff[i].byte, ", addr: ", cast[int](buff) + i
      if strbuff[i] == '\0':
        inc nullchars
        if nullchars == 2:
          running = false
        else:
          #echo "str at ", cast[int](buff) + strBegin
          result.add $cast[WinString](cast[int](buff) + strBegin)
          strBegin = i + 1
      else:
        nullchars = 0
      inc(i)

proc readInt32*(handle: RegHandle, key: string): int32 {.sideEffect.} =
  ## reads value of type ``REG_DWORD`` from registry key. The key must have
  ## been opened with the ``samQueryValue`` access right.
  var
    size: DWORD = sizeof(result).DWORD
    keyWS = allocWinString(key)
    status = regGetValue(handle, nil, keyWS, RRF_RT_REG_DWORD, nil,
      result.addr, size.addr)
  regThrowOnFail(status)

proc readInt64*(handle: RegHandle, key: string): int64 {.sideEffect.} =
  ## reads value of type ``REG_QWORD`` from registry entry. The key must have
  ## been opened with the ``samQueryValue`` access right.
  var
    size: DWORD = sizeof(result).DWORD
    keyWS = allocWinString(key)
    status = regGetValue(handle, nil, keyWS, RRF_RT_REG_QWORD, nil,
      result.addr, size.addr)
  regThrowOnFail(status)

proc readBinary*(handle: RegHandle, key: string): seq[byte] {.sideEffect.} =
  ## reads value of type ``REG_BINARY`` from registry entry. The key must have
  ## been opened with the ``samQueryValue`` access right.
  injectRegKeyReader(handle, key, RRF_RT_REG_BINARY)
  result = newSeq[byte](size)
  copyMem(result[0].addr, buff, size)
  dealloc(buff)

proc delSubkey*(handle: RegHandle, subkey: string,
  samDesired: RegKeyRights = samDefault) {.sideEffect.} =
  ## deletes a subkey and its values from the specified platform-specific
  ## view of the registry. Note that key names are not case sensitive.
  ## The subkey to be deleted must not have subkeys. To delete a key and all it
  ## subkeys, you need to enumerate the subkeys and delete them individually.
  ## To delete keys recursively, use the `delTree<#delTree>`_.
  ##
  ## `samDesired` should be ``samWow32`` or ``samWow64``.
  regThrowOnFail(regDeleteKeyEx(handle, allocWinString(subkey), samDesired,
    0.DWORD))

proc delTree*(handle: RegHandle, subkey: string) {.sideEffect.} =
  ## deletes the subkeys and values of the specified key recursively. `subkey`
  ## can be ``nil``, in that case, all subkeys of `handle` is deleted.
  ##
  ## The key must have been opened with ``samDelete``, ``samEnumSubkeys``
  ## and ``samQueryValue`` access rights.
  let winSubkey = if subkey.len == 0: cast[WinString](nil) 
                  else: allocWinString(subkey)
  regThrowOnFail(regDeleteTree(handle, winSubkey))

proc expandEnvString*(str: string): string =
  ## helper proc to expand strings returned by
  ## `readExpandString<#readExpandString>`_ proc. If string cannot be expanded,
  ## empty string is returned.
  ##
  ## .. code-block:: nim
  ##  echo expandEnvString("%PATH%") # => C:\Windows;C:\Windows\system32...
  var
    size: DWORD = 32 * sizeof(WinChar)
    buff: pointer = alloc(size)
    valueWS = allocWinString(str)
  var returnValue = expandEnvironmentStrings(valueWS, buff, size)
  if returnValue == 0:
    dealloc(buff)
    return ""
  # return value is in TCHARs, aka number of chars returned, not number of
  # bytes required to store string
  # WinChar is `char` or `Utf16Char` depending on useWinUnicode const in winlean
  # actually needs to be checked because without this line everything works okay
  returnValue = returnValue * sizeof(WinChar).DWORD
  if returnValue > size:
    # buffer size was not enough to expand string
    size = returnValue
    buff = realloc(buff, size)
    returnValue = expandEnvironmentStrings(valueWS, buff, size)
  if returnValue == 0:
    dealloc(buff)
    return ""
  result = $(cast[WinString](buff))
  dealloc(buff)

when compileOption("taintmode"):
  proc expandEnvString*(str: TaintedString): string =
    ## expandEnvString for TaintedString.
    expandEnvString(str.string)

when isMainModule:
  import sequtils

  var passed = true
  var msg, stacktrace: string
  var handle, innerHandle: RegHandle
  try:
    handle = createOrOpen("HKEY_LOCAL_MACHINE\\Software\\AAAnim_reg_test",
      samRead or samWrite or samWow32)

    # String
    handle.writeString("StringValue", "StringData")
    assert(handle.readString("StringValue").string == "StringData")
    handle.writeString("StringPathValue", "C:\\Dir\\File")
    assert(handle.readString("StringPathValue").string == "C:\\Dir\\File")
    
    # Binary
    handle.writeBinary("BinaryValue", [0xff.byte, 0x00])
    let binaryData = handle.readBinary("BinaryValue")
    assert(binaryData[0] == 0xff)
    assert(binaryData[1] == 0x00)
    
    # Int32
    handle.writeInt32("Int32Value", 1000)
    assert(handle.readInt32("Int32Value") == 1000)
    handle.writeInt32("Int32ValueMin", -2147483647)
    assert(handle.readInt32("Int32ValueMin") == -2147483647)
    handle.writeInt32("Int32ValueMax", 2147483647)
    assert(handle.readInt32("Int32ValueMax") == 2147483647)

    # Int64
    handle.writeInt64("Int64Value", 1000)
    assert(handle.readInt64("Int64Value") == 1000)
    handle.writeInt64("Int64ValueMin", -9223372036854775807)
    assert(handle.readInt64("Int64ValueMin") == -9223372036854775807)
    handle.writeInt64("Int64ValueMax", 9223372036854775807)
    assert(handle.readInt64("Int64ValueMax") == 9223372036854775807)

    # Expand String
    handle.writeExpandString("ExpandStringValue", "%PATH%")
    assert(handle.readExpandString("ExpandStringValue").expandEnvString() != "%PATH%")

    # Multi String
    handle.writeMultiString("MultiStringValue", ["Hello, world!", "\u03AB世界", "世ϵ界", ""])
    var multiString = handle.readMultiString("MultiStringValue")
    assert(multiString.len == 3)
    assert(multiString[0] == "Hello, world!")
    assert(multiString[1] == "\u03AB世界")
    assert(multiString[2] == "世ϵ界")

    # Key/subkey/value operations
    innerHandle = create(handle, "InnerKey", samAll)
    assert(innerHandle.countSubkeys() == 0)
    var numValues = innerHandle.countValues() 
    assert(numValues == 0)
    assert(numValues == toSeq(innerHandle.enumValueNames()).len)

    innerHandle.writeString("InnerStringValue", "Hello")
    numValues = innerHandle.countValues()
    var valueNames = toSeq(innerHandle.enumValueNames())
    assert(numValues == 1)
    assert(numValues == valueNames.len)
    assert(valueNames[0] == "InnerStringValue")

    close(innerHandle)

    assert(handle.countSubkeys() == 1)
    innerHandle = create(handle, "InnerKey_second", samAll)
    close(innerHandle)
    innerHandle = 0.RegHandle

    assert(handle.countSubkeys() == 2)
    delSubkey(handle, "InnerKey")
    assert(handle.countSubkeys() == 1)
    delTree(handle, "")
    assert(handle.countSubkeys() == 0)

    close(handle)
    handle = 0.RegHandle

    # delSubkey(HKEY_LOCAL_MACHINE, "Software\\AAAnim_reg_test", samWow32)
  except RegistryError, AssertionError:
    passed = false
    msg = getCurrentExceptionMsg()
    stacktrace = getStackTrace(getCurrentException())
  finally:
    close(handle)
    close(innerHandle)
    if passed:
      echo "tests passed"
      quit(QuitSuccess)
    else:
      echo "tests failed: ", msg
      echo stacktrace
      quit(QuitFailure)

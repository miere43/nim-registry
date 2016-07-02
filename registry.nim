## represents module which provides access to Windows registry.

## .. include:: doc/modulespec.rst 
include "private/winregistry"

type
  RegistryError = object of Exception

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
  of "HKEY_CLASSES_ROOT": return HKEY_CLASSES_ROOT
  of "HKEY_CURRENT_USER": return HKEY_CURRENT_USER
  of "HKEY_LOCAL_MACHINE": return HKEY_LOCAL_MACHINE
  of "HKEY_USERS": return HKEY_USERS
  of "HKEY_PERFORMANCE_DATA": return HKEY_PERFORMANCE_DATA
  of "HKEY_CURRENT_CONFIG": return HKEY_CURRENT_CONFIG
  of "HKEY_DYN_DATA": return HKEY_DYN_DATA
  else: return 0.RegHandle

proc parseRegPath(path: string, outSubkey: var string): RegHandle =
  var rootStr: string
  if not splitRegPath(path, rootStr, outSubkey):
    raise newException(RegistryError, "invalid path")
  result = getPredefinedRegHandle(rootStr)
  if result == 0.RegHandle:
    raise newException(RegistryError, "unsupported path root")

proc allocWinString(str: string): WinString {.inline.} =
  when declared(useWinUnicode):
    if str == nil:
      return WideCString(nil)
    return newWideCString(str)
  else:
    return cstring(str)

proc regThrowOnFailInternal(hresult: LONG): void =
  when defined(debug):
    const langid = 1033 # show english error msgs
  else:
    const langid = 0
  var result: string = nil
  when useWinUnicode:
    var msgbuf: WideCString
    if formatMessageW(0x00000100 or 0x00001000 or 0x00000200,
                      nil, hresult.int32, langid, msgbuf.addr, 0, nil) != 0'i32:
      result = $msgbuf
      if msgbuf != nil: localFree(cast[pointer](msgbuf))
  else:
    var msgbuf: cstring
    if formatMessageA(0x00000100 or 0x00001000 or 0x00000200,
                    nil, hresult.int32, langid, msgbuf.addr, 0, nil) != 0'i32:
      result = $msgbuf
      if msgbuf != nil: localFree(msgbuf)
  if result == nil:
    raise newException(RegistryError, "unknown error")
  else:
    raise newException(RegistryError, result)

template regThrowOnFail(hresult: LONG) =
  if hresult != ERROR_SUCCESS:
    regThrowOnFailInternal(hresult)

template injectRegPathSplit(path: string) =
  var subkey {.inject.}: string
  var root {.inject.}: RegHandle = parseRegPath(path, subkey)

proc createKeyInternal(handle: RegHandle, subkey: string,
  samDesired: RegKeyRights, outHandle: ptr RegHandle): LONG =
  regThrowOnFail(regCreateKeyEx(handle, allocWinString(subkey), 0.DWORD, nil,
    0.DWORD, samDesired, nil, outHandle, result.addr))

proc create*(handle: RegHandle, subkey: string,
    samDesired: RegKeyRights): RegHandle {.sideEffect.} =
  ## creates new `subkey`. ``RegistryError`` is raised if key already exists.
  if createKeyInternal(handle, subkey, samDesired, result.addr) !=
      REG_CREATED_NEW_KEY:
    raise newException(RegistryError, "key already exists")
  
proc create*(path: string, samDesired: RegKeyRights): RegHandle {.inline.} =
  ## creates new `subkey`. ``RegistryError`` is raised if key already exists.
  injectRegPathSplit(path)
  create(root, subkey, samDesired)

proc createOrOpen*(handle: RegHandle, subkey: string,
    samDesired: RegKeyRights): RegHandle {.sideEffect.} =
  ## same as `create(...)`, but does not raise ``RegistryError`` if key already
  ## exists.
  discard createKeyInternal(handle, subkey, samDesired, result.addr)

proc createOrOpen*(path: string, samDesired: RegKeyRights): RegHandle =
  ## same as `create(...)`, but does not raise ``RegistryError`` if key already
  ## exists.
  injectRegPathSplit(path)
  result = createOrOpen(root, subkey, samDesired)

proc open*(handle: RegHandle, subkey: string,
    samDesired: RegKeyRights = samDefault): RegHandle {.sideEffect.} =
  ## opens the specified registry key. Note that key names are
  ## not case sensitive. Raises ``RegistryError`` when `handle` is invalid or
  ## `subkey` does not exist.
  regThrowOnFail(regOpenKeyEx(handle, allocWinString(subkey), 0.DWORD,
    samDesired, result.addr))

proc open*(path: string, samDesired: RegKeyRights = samDefault): RegHandle
    {.sideEffect.} =
  ## same as `open`, but enables specifying path without using root `RegHandle`
  ## constants.
  injectRegPathSplit(path)
  result = open(root, subkey, samDesired) 

proc close*(handle: RegHandle) {.sideEffect.} =
  ## closes a registry `handle`. After using this proc, `handle` is no longer
  ## valid and should not be used with any registry procedures. Try to close
  ## registry handles as soon as possible.
  discard regCloseKey(handle)

proc writeString*(handle: RegHandle, path, subkey, value: string): LONG
    {.sideEffect.} = 
  var valueWC = allocWinString(value)
  return regSetKeyValue(handle, allocWinString(path), allocWinString(subkey),
    regSZ, valueWC.addr, (len(valueWC) + 1).DWORD)

template injectRegKeyReader(handle: RegHandle, key: string,
  allowedDataTypes: DWORD) {.immediate.} =
  ## dont forget to dealloc buffer
  var
    size: DWORD = 32
    buff {.inject.}: pointer = alloc(size)
    kind: RegValueKind
    keyWS = allocWinString(key)
  var returnValue = regGetValue(handle, nil, keyWS, allowedDataTypes, kind.addr,
    buff, size.addr)
  if returnValue == ERROR_MORE_DATA:
    # TODO: impl. for HKEY_PERFORMANCE_DATA
    dealloc(buff)
    # size now stores amount of bytes, required to store value in array
    buff = alloc(size)
    returnValue = regGetValue(handle, nil, keyWS, allowedDataTypes, kind.addr,
      buff, size.addr)
  regThrowOnFail(returnValue)

proc readString*(handle: RegHandle, key: string, value: var string)
    {.sideEffect.} =
  ## reads value of type ``REG_SZ`` from registry entry.
  injectRegKeyReader(handle, key, RRF_RT_REG_SZ)
  value = $(cast[WinString](buff))
  dealloc(buff)

proc readString*(handle: RegHandle, key: string): string {.inline.} =
  ## reads value of type ``REG_SZ`` from registry entry.
  readString(handle, key, result)

proc readInt32*(handle: RegHandle, key: string, value: var int32)
    {.sideEffect.} =
  ## reads value of type ``REG_DWORD`` from registry entry.
  injectRegKeyReader(handle, key, RRF_RT_REG_DWORD)
  var intbuff = cast[cstring](buff)
  value = int32(byte(intbuff[0])) or (int32(byte(intbuff[1])) shl 8) or
    (int32(byte(intbuff[2])) shl 16) or (int32(byte(intbuff[3])) shl 24)
  dealloc(buff)

proc readInt32*(handle: RegHandle, key: string): int32 {.inline, sideEffect.} =
  ## reads value of type ``REG_DWORD`` from registry entry.
  readInt32(handle, key, result)

proc readInt64*(handle: RegHandle, key: string, value: var int64)
    {.sideEffect.} =
  ## reads value of type ``REG_QWORD`` from registry entry.
  injectRegKeyReader(handle, key, RRF_RT_REG_QWORD)
  var intbuff = cast[cstring](buff)
  value = int64(byte(intbuff[0])) or (int64(byte(intbuff[1])) shl 8) or
    (int64(byte(intbuff[2])) shl 16) or (int64(byte(intbuff[3])) shl 24) or
    (int64(byte(intbuff[4])) shl 32) or (int64(byte(intbuff[5])) shl 40) or
    (int64(byte(intbuff[6])) shl 48) or (int64(byte(intbuff[7])) shl 56)
  dealloc(buff)

proc readInt64*(handle: RegHandle, key: string): int64 {.inline, sideEffect.} =
  ## reads value of type ``REG_QWORD`` from registry entry.
  readInt64(handle, key, result)

proc delKey*(handle: RegHandle, subkey: string,
    samDesired: RegKeyRights = samDefault) {.sideEffect.} =
  ## deletes a subkey and its values from the specified platform-specific
  ## view of the registry. Note that key names are not case sensitive.
  ## The subkey to be deleted must not have subkeys. To delete a key and all it
  ## subkeys, you need to enumerate the subkeys and delete them individually.
  ## To delete keys recursively, use the ``delTree``.
  ##
  ## `samDesired` should be ``samWow32`` or ``samWow64``.
  regThrowOnFail(regDeleteKeyEx(handle, allocWinString(subkey),
    samDesired,0.DWORD))

proc delTree*(handle: RegHandle, subkey: string) {.sideEffect.} =
  ## deletes the subkeys and values of the specified key recursively.
  regThrowOnFail(regDeleteTree(handle, allocWinString(subkey)))

when isMainModule:
  var pass: bool = true
  var msg: string
  var h: RegHandle
  try:
    var
      faceName: string
      fontSize: int32
      fontWeight: int32 
    h = open("HKEY_CURRENT_USER\\Console\\Git Bash", samRead)
    h.readString("FaceName", faceName)
    h.readInt32("FontSize", fontSize)
    h.readInt32("FontWeight", fontWeight)
    close(h)
  except RegistryError, AssertionError:
    pass = false
    msg = getCurrentExceptionMsg()
  finally:
    close(h)
    if pass:
      echo "tests passed"
    else:
      echo "tests failed: ", msg

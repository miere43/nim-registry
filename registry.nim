## represents module which provides access to Windows registry.

## .. include:: doc/modulespec.rst 
include "private/winregistry"

type
  RegistryError = object of Exception

iterator splitRegPath(path: string): string =
  var sliceStart = 0
  var sliceEnd = 0
  for c in path:
    if c == '\\':
      var s = substr(path, sliceStart, sliceEnd - 1)
      yield s
      inc sliceEnd
      sliceStart = sliceEnd
    else:
      inc sliceEnd
  if sliceStart != sliceEnd:
    yield substr(path, sliceStart, sliceEnd)

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

# proc setRegKeyValue(regPath, subkey, value: string): void =
#   var prevreg: HKEY = 0
#   var reg: HKEY = 0
#   var isFirst = true
#   var key: string
#   for rp in splitRegPath(regPath):
#     echo "CHECKING: '", rp, "'"
#     prevreg = reg
#     if isFirst:
#       reg = getPredefinedHKEY(rp)
#       assert(reg != 0)
#       isFirst = false
#     else:
#       assert(prevreg != 0)
#       assert(0 == regOpenKeyEx(prevreg, cstring(rp), DWORD(0), DWORD(0), 
#         addr(reg)))
#       assert(0 == regCloseKey(prevreg))
#     key = rp
#   assert(reg != 0)
#   assert(0 == regSetKeyValue(reg, cstring(key), cstring(subkey), regSZ,
#     cstring(value), (len(value) + 1).DWORD))
#   assert(0 == regCloseKey(reg))

proc allocWinString(str: string): WinString {.inline.} =
  when declared(useWinUnicode):
    if str == nil:
      return WideCString(nil)
    return newWideCString(str)
  else:
    return cstring(str)

proc regThrowOnFail(hresult: LONG): void =
  if hresult == ERROR_SUCCESS:
    return
  var result: string = nil
  when useWinUnicode:
    var msgbuf: WideCString
    if formatMessageW(0x00000100 or 0x00001000 or 0x00000200,
                      nil, hresult.int32, 1033, addr(msgbuf), 0, nil) != 0'i32:
      result = $msgbuf
      if msgbuf != nil: localFree(cast[pointer](msgbuf))
  else:
    var msgbuf: cstring
    if formatMessageA(0x00000100 or 0x00001000 or 0x00000200,
                    nil, hresult.int32, 1033, addr(msgbuf), 0, nil) != 0'i32:
      result = $msgbuf
      if msgbuf != nil: localFree(msgbuf)
  if result == nil:
    raise newException(RegistryError, "unknown error")
  else:
    raise newException(RegistryError, result)

proc open*(handle: RegHandle, subkey: string,
    samDesired: RegKeyRights = samDefault): RegHandle {.sideEffect.} =
  ## opens the specified registry key. Note that key names are
  ## not case sensitive. Raises ``RegistryError`` when `handle` is invalid or
  ## `subkey` does not exist.
  regThrowOnFail(regOpenKeyEx(handle, allocWinString(subkey), 0.DWORD,
    samDesired, result.addr))

proc close*(handle: RegHandle) {.sideEffect.} =
  ## closes a registry `handle`. After using this proc, `handle` is no longer
  ## valid and should not be used with any registry procedures. Try to close
  ## registry handles as soon as possible.
  discard regCloseKey(handle)

proc open*(path: string, samDesired: RegKeyRights = samDefault): RegHandle
    {.sideEffect.} =
  ## same as `open`
  var prev, curr: RegHandle
  var first: bool = true
  for hkey in splitRegPath(path):
    if first:
      first = false
      prev = open(getPredefinedRegHandle(hkey), nil, samDesired)
      continue
    curr = open(prev, hkey, samDesired)
    close(prev)
    prev = curr
  result = curr 

proc writeValue*(handle: RegHandle, path, subkey, value: string): LONG
    {.sideEffect.} = 
  var valueWC = allocWinString(value)
  return regSetKeyValue(handle, allocWinString(path), allocWinString(subkey),
    regSZ, valueWC.addr, (len(valueWC) + 1).DWORD)

proc getString*(handle: RegHandle, subkey, key: string, 
    bufferLength: Natural = 64): string {.sideEffect.} =
  ## retrieves the specified registry string value. Only values of type
  ## ``REG_SZ`` and ``REG_EXPAND_SZ`` are returned, others produce ``nil``.
  var buff: pointer = alloc(bufferLength)
  var size: DWORD = bufferLength
  var kind: RegValueKind
  let retval = regGetValue(handle, allocWinString(subkey), allocWinString(key),
    (RRF_RT_REG_SZ or RRF_RT_REG_EXPAND_SZ).DWORD, kind.addr, buff, size.addr)
  if retval == ERROR_MORE_DATA:
    # now `size` variable stores buffer length, required to store data
    return getString(handle, subkey, key, size)
  if retval != ERROR_SUCCESS:
    return nil
  # now `size` variable stores amount of chars, required to construct string
  return $(cast[WinString](buff))

proc getString*(handle: RegHandle, key: string,
    bufferLength: Natural = 64): string {.inline.} =
  ## alias of `getString(handle, nil, key, bufferLength)`. Use when you do not
  ## need to access subkey.
  return getString(handle, nil, key, bufferLength)

proc delKey*(handle: RegHandle, subkey: string,
    samDesired: RegKeyRights = samDefault) {.sideEffect.} =
  ## deletes a subkey and its values from the specified platform-specific
  ## view of the registry. Note that key names are not case sensitive.
  ## The subkey to be deleted must not have subkeys. To delete a key and all it
  ## subkeys, you need to enumerate the subkeys and delete them individually.
  ## To delete keys recursively, use the ``deleteRegTree``.
  ##
  ## `samDesired` should be ``samWow6464Key`` or ``samWow6432Key``.
  regThrowOnFail(regDeleteKeyEx(handle, allocWinString(subkey),
    samDesired,0.DWORD))

proc delTree*(handle: RegHandle, subkey: string) {.sideEffect.} =
  ## deletes the subkeys and values of the specified key recursively.
  regThrowOnFail(regDeleteTree(handle, allocWinString(subkey)))

# template withRegKey(handle: RegHandle, body: untyped): expr =
#   try:
#     body
#   finally:
#     closeRegKey(handle)

when isMainModule:
  var pass: bool = true
  try:
    var kc = open("HKEY_CURRENT_USER\\Console\\Git Bash", samRead)
    echo kc.getString("FaceName")
    close(kc)
  except RegistryError:
    pass = false
  finally:
    if pass:
      echo "tests passed"
    else:
      echo "tests failed: ", getCurrentExceptionMsg()

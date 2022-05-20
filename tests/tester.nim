import sequtils, winregistry, winlean

echo "unicode: " & $useWinUnicode

var passed = true
var msg, stacktrace: string
var handle, innerHandle: RegHandle
try:
  handle = createOrOpen("HKEY_LOCAL_MACHINE\\Software\\AAAnim_reg_test",
    samRead or samWrite or samWow32)

  # String
  handle.writeString("StringValue", "StringData")
  assert(handle.readString("StringValue") == "StringData")
  handle.writeString("StringPathValue", "C:\\Dir\\File")
  assert(handle.readString("StringPathValue") == "C:\\Dir\\File")
  
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
except OSError, AssertionDefect:
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

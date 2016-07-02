# nim-registry

Deal with Windows Registry from Nim.

```nim
import registry

var
  faceName: string
  fontSize: int32
  fontWeight: int32 

try:
  var h = open("HKEY_CURRENT_USER\\Console\\Git Bash", samRead)
  h.readString("FaceName", faceName)
  h.readInt32("FontSize", fontSize)
  h.readInt32("FontWeight", fontWeight)
except RegistryError:
  echo "err: ", getCurrentExceptionMsg()
finally:
  close(h)
```

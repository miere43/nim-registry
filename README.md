# nim-registry

Deal with Windows Registry from Nim.

```nim
import registry

var
  faceName: string
  fontSize: int32
  fontWeight: int32 
  h: RegHandle

try:
  h = open("HKEY_CURRENT_USER\\Console\\Git Bash", samRead)
  faceName = h.readString("FaceName")
  fontSize = h.readInt32("FontSize")
  fontWeight = h.readInt32("FontWeight")
except RegistryError:
  echo "err: ", getCurrentExceptionMsg()
finally:
  close(h)
```

## TODO
* impl. `read/writeBinary`, `read/writeMultiString`
* test with `useWinAscii`
* add tests

# nim-registry

Deal with Windows Registry from Nim.

Online docs here: http://miere.ru/docs/registry/

```nim
import winregistry

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

## Tests
Run in command line:
```
$ nim c -r winregistry
$ nim c -r -d:useWinAnsi winregistry
```
You should see a "tests passed" message.

## Changelog
### 0.2.1
- Added "enumValueNames"
- Fixed missing dealloc in case of exception in "enumSubkeys"

### 0.2.0
- Updated for nim 0.19.0

### 0.1.8
- Fixed GC-unsafe procs to be safe

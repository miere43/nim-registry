# nim-registry

Deal with Windows Registry from Nim.

Online docs here: http://miere.ru/docs/registry/

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

## Tests
Run in command line:
```
$ nim c -r registry.nim
$ nim c -r -d:useWinAnsi registry.nim
```
You should see a "tests passed" message.

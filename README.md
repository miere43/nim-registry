# nim-registry

Deal with Windows Registry from Nim.

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
except OSError:
  echo "err: ", getCurrentExceptionMsg()
finally:
  close(h)
```

## Tests
Run in command line:
```
$ nimble test
```
You should see a "tests passed" message. If you get `Access is denied` error, try running with administrator rights.

## Changelog
### 2.0.0
- Added support for Nim 2.0.0
- Removed support for `useWinUnicode` switch
- `WinString` type was removed; use `WideCString` instead

### 1.0.0
- `RegValueKind` and `RegKeyRights` are distinct `uint32`'s now (fixed warning about enums with holes).
- Replaced `RegistryError` with `OSError` for consistency with built-in `registry` package.
- Removed support for deprecated `taintmode` feature.
- Moved tests out of main file to ensure things are exported correctly.
- Fixed deprecation/unused variable warnings.
- Updated documentation.
- Nim 1.6.0 is now minimum supported version.

### 0.2.1
- Added "enumValueNames"
- Fixed missing dealloc in case of exception in "enumSubkeys"

### 0.2.0
- Updated for nim 0.19.0

### 0.1.8
- Fixed GC-unsafe procs to be safe

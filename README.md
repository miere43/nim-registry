# nim-registry

Deal with Windows Registry from Nim.

```nim
import registry

var handle = open("HKEY_CURRENT_USER\\Console\\Git Bash", samRead)
echo getString(handle, "FontName") # => Lucida Console
close(handle)
```

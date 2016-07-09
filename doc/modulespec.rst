	Please do not use this module to save your applications settings, use it to interact with older programs which make use of registry, because it is slow (implemented as file system inside a file rather than database), not cross-platform, has unoblivious stuff like registry virtualization, virtual storages, different behavior across 32/64-bit systems. As alternative you can supply some kind of INI or XML file with your application or store it into platform-specific settings folder (take a look at `appdirs module <https://github.com/MrJohz/appdirs>`_).

Notes
-----

* When writing UTF-16 chars in ``useWinAnsi`` mode using ``writeMultiString`` you will see garbage if you view that string in registry, but ``readMultiString`` will decode it correctly.
* Registry paths use backslashes ``(\)``, forwardslashes ``(/)`` are parsed as normal characters.
* Module procs' do not convert values from UTF-16 to UTF-8, howerer, when ``useWinAnsi`` defined, Windows handles conversion from UTF-16 strings to ASCII.
* If some procs throw ``RegistryError``, but everything seems okay, make sure registry handle have proper security rights.
* Registry on MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724871(v=vs.85).aspx
* Note that registry entries may be stored separately for 32/64-bit applications: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724072(v=vs.85).aspx
* ``Read about Registry Virtualization``: https://msdn.microsoft.com/en-us/library/windows/desktop/aa965884(v=vs.85).aspx
* Registry keys affected by WOW64: https://msdn.microsoft.com/en-us/library/windows/desktop/aa384253(v=vs.85).aspx

.. code-block::nim
  # actually opens HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Adobe
  var a = open("HKEY_LOCAL_MACHINE\\SOFTWARE\\Adobe", samRead)
  # now it is properly opened HKEY_LOCAL_MACHINE\Software\Adobe
  var b = open("HKEY_LOCAL_MACHINE\\SOFTWARE\\Adobe", samRead or samWow64)
  # actually creates HKEY_USERS\<User SID>_Classes\VirtualStore\Machine\Software\test
  var c = create("HKEY_LOCAL_MACHINE\\SOFTWARE\\test")

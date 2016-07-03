Notes
=====

* ``Warning:`` Read procs for ``HKEY_PERFORMANCE_*`` handles are not implemented properly and may raise ``RegistryError``.
* Registry paths use backslashes ``(\)``, forwardslashes ``(/)`` are parsed as normal characters.
* Module procs' do not convert values from UTF-16 to UTF-8, howerer, when ``useWinAnsi`` defined, Windows handles conversion from UTF-16 strings to ASCII.
* If some procs throw ``RegistryError``, but everything seems okay, make sure registry handle have proper security rights.
* Registry on MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724871(v=vs.85).aspx
* Note that registry entries may be stored separately for 32/64-bit applications: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724072(v=vs.85).aspx

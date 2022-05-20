# package
version     = "1.0.0"
author      = "Vladislav <miere> Vorobiev"
description = "Deal with Windows Registry from Nim"
license     = "MIT"

# deps 
requires      "nim >= 1.6.0"

task test, "Runs the test suite":
  exec "nim c -r tests/tester"

task testansi, "Runs the test suite (ANSI)":
  exec "nim c -d:useWinAnsi -r tests/tester"

@echo off
setlocal enableextensions

set "SRC32=bin\Release\Win32"
if not exist "%SRC32%\TitanEngine.dll" set "SRC32=Release\x32"

set "SRC64=bin\Release\x64"
if not exist "%SRC64%\TitanEngine.dll" set "SRC64=Release\x64"

if exist deps rmdir /s /q deps
mkdir deps\x32
mkdir deps\x64
copy /y "%SRC32%\TitanEngine.dll" deps\x32\TitanEngine.dll
copy /y "%SRC32%\TitanEngine.pdb" deps\x32\TitanEngine.pdb
copy /y "%SRC64%\TitanEngine.dll" deps\x64\TitanEngine.dll
copy /y "%SRC64%\TitanEngine.pdb" deps\x64\TitanEngine.pdb

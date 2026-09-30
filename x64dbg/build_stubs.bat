@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1
cd /d "%~dp0compat_stubs"
for %%S in (x64dbg x64bridge x64gui) do (
    cl /nologo /LD %%S.c /link /NOENTRY
    if errorlevel 1 exit /b 1
)

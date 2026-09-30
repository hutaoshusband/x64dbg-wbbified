@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1
cd /d "%~dp0"
cl /nologo /O1 exitmark.c /Fe:exitmark.exe
if errorlevel 1 exit /b 1
cl /nologo /Od bpmain.c /Fe:bpmain.exe
if errorlevel 1 exit /b 1
cl /nologo /O1 probe.c /Fe:probe.exe
if errorlevel 1 del /q *.obj >nul 2>&1 & exit /b 1
del /q *.obj >nul 2>&1

@echo off

cd /d "%~dp0"

set PORTABLE_PYTHON=%~dp0python-2.7.18.amd64.portable
if not exist "%PORTABLE_PYTHON%\python.exe" (
	echo Downloading portable Python...
	curl.exe --fail --location --retry 3 --retry-delay 2 --output python-2.7.18.amd64.portable.7z https://github.com/x64dbg/docs/releases/download/python27-portable/python-2.7.18.amd64.portable.7z
	if errorlevel 1 (
		echo ERROR: Failed to download portable Python from GitHub Releases.
		echo The server may be temporarily unavailable; check the curl error above and retry later.
		del /Q python-2.7.18.amd64.portable.7z 2>nul
		exit /b 1
	)
	7z x python-2.7.18.amd64.portable.7z -opython-2.7.18.amd64.portable
	if errorlevel 1 (
		echo ERROR: The portable Python download is not a valid 7z archive.
		exit /b 1
	)
)

if not exist "%~dp0hhc.exe" (
	echo Downloading HTML Help Workshop...
	curl.exe --fail --location --retry 3 --retry-delay 2 --output hhc-4.74.8702.7z https://github.com/x64dbg/deps/releases/download/dependencies/hhc-4.74.8702.7z
	if errorlevel 1 (
		echo ERROR: Failed to download HTML Help Workshop from GitHub Releases.
		echo The server may be temporarily unavailable; check the curl error above and retry later.
		del /Q hhc-4.74.8702.7z 2>nul
		exit /b 1
	)
	7z x hhc-4.74.8702.7z
	if errorlevel 1 (
		echo ERROR: The HTML Help Workshop download is not a valid 7z archive.
		exit /b 1
	)
)

echo Building Help Project
call make htmlhelp
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
echo Applying CHM hacks
copy theme.js .\_build\htmlhelp\_static\js\theme.js
type hacks.css >> .\_build\htmlhelp\_static\css\theme.css
echo Generating keyword index
"%PORTABLE_PYTHON%\python.exe" genhhk.py .\_build\htmlhelp\x64dbgdoc.hhp
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
echo Building CHM File
hhc.exe .\_build\htmlhelp\x64dbgdoc.hhp
copy /Y .\_build\htmlhelp\x64dbgdoc.chm x64dbg.chm
if not exist "x64dbg.chm" (
	echo Failed to build CHM file!
	exit /b 1
)
echo Finished

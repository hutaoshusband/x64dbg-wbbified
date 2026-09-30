@echo off
setlocal enableextensions
if exist release rmdir /s /q release
md release\x32\GleeBug
md release\x32\StaticEngine
md release\x64\GleeBug
md release\x64\StaticEngine

copy /y bin\Release\x32\TitanEngine.dll release\x32\GleeBug\TitanEngine.dll
copy /y bin\Release\x32\TitanEngine.pdb release\x32\GleeBug\TitanEngine.pdb
copy /y bin\Release\x32\TitanEngine.dll release\x32\StaticEngine\TitanEngine.dll
copy /y bin\Release\x32\TitanEngine.pdb release\x32\StaticEngine\TitanEngine.pdb

copy /y bin\Release\x64\TitanEngine.dll release\x64\GleeBug\TitanEngine.dll
copy /y bin\Release\x64\TitanEngine.pdb release\x64\GleeBug\TitanEngine.pdb
copy /y bin\Release\x64\TitanEngine.dll release\x64\StaticEngine\TitanEngine.dll
copy /y bin\Release\x64\TitanEngine.pdb release\x64\StaticEngine\TitanEngine.pdb

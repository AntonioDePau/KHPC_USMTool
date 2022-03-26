@echo off

set msbuild=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\msbuild.exe
echo.%1
"%msbuild%" %1

pause
@echo off
set "VSDLL=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
set "TARGET_DIR=D:\logforai\InjectBambooRO"

echo [1/2] Starting Visual Studio Dev Shell and Navigating to Directory...

C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -noexit -command "& {Import-Module '%VSDLL%'; Enter-VsDevShell b6423c22; cd '%TARGET_DIR%'; echo '[2/2] Compiling...'; cl.exe /LD /O2 /W3 hybridge.cpp /Fe:version.dll ws2_32.lib /link /DLL}"
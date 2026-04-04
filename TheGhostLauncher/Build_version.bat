@echo off
set "VSDLL=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
set "TARGET_DIR=D:\logforai\TheGhostLauncher"

echo [1/2] Starting Visual Studio Dev Shell and Navigating to Directory...

C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -noexit -command "& {Import-Module '%VSDLL%'; Enter-VsDevShell b6423c22; cd '%TARGET_DIR%'; echo '[2/2] Compiling...'; cl.exe /LD /O2 /W3 /D "WIN32" /D "NDEBUG" /D "NETREDIRECT_EXPORTS" /D "_WINDOWS" /D "_USRDLL" /D "_UNICODE" /D "UNICODE" /I"packages\Detours.4.0.1\lib\native\include" NetRedirect.cpp NetRedirect-utils.cpp pch.cpp /link /LIBPATH:"packages\Detours.4.0.1\lib\native\libs\x86" detours.lib ws2_32.lib kernel32.lib user32.lib /OUT:NetRedirect.dll}"
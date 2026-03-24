Project > Bypass Gepard Shield V.3 (Bamboo)

1.TheGhostLauncher
Build File Client.exe(ปลอม) เพื่อเรียกอ่านไฟล์ version.dll(สามารถเปลี่ยนได้)

2.Find Packet
For Received Packet From.exe (Output : C:\Users\Public\Bamboo_analysis.log)

3.Bild Inject file:
Run > Developer Powershell for VScode
cd "D:\logforai" (Path)
cl /LD /O2 /W3 hybridge.cpp /Fe:version.dll ws2_32.lib /link /DLL

4.วิธีหา dump files
Run idle Client.exe
dumpbin /IMPORTS "C:\Users\User\Downloads\BambooRO_v6\BambooRO_v6\BamBoo_Client.exe" > imports.txt
// Proof of Concept code to download chrome.dll symbols from chromium symbols store and find the bssl::kTLSProtocolMethod table of pointers (usually hooked by malware)
//
// Author : Javier Vicente Vallejo
// Twitter : @vallejocc
// Web : http://www.vallejo.cc
//
// I recommend to read this fantastic article about the API to download symbols: https://gregsplaceontheweb.wordpress.com/2015/08/15/how-to-download-windows-image-files-from-the-microsoft-symbol-server-using-c-and-dbghelp/
//

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <DbgHelp.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <shlwapi.h>

void main()
{
	#define symbolssrvW L"SRV*c:\\symcache*https://chromium-browser-symsrv.commondatastorage.googleapis.com"
	#define symbolssrvA "SRV*c:\\symcache*https://chromium-browser-symsrv.commondatastorage.googleapis.com"
	//#define symbolssrvW L"SRV*c:\\symcache*https://msdl.microsoft.com/download/symbols"
	//#define symbolssrvA "SRV*c:\\symcache*https://msdl.microsoft.com/download/symbols"
	#define symsrvpath "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\"

	BOOL (WINAPI *pSymbolServerStoreFile)(
		PCTSTR SrvPath,
		PCTSTR FileName,
		GUID id,
		DWORD  val2,
		DWORD  val3,
		PSTR   StoredPath,
		size_t cStoredPath,
		DWORD  Flags
	);

	DWORD cbNeeded;
	unsigned int i;
	HANDLE h;
	GUID guid;
	DWORD v1;
	DWORD v2;
	DWORD res;
	DWORD64 res64;
	DWORD64 mbase;		
	PROCESSENTRY32 entry;
	IMAGEHLP_MODULE64 minfo;
	SYMBOL_INFO symbol;
	
	char * buf = malloc(0x2000);
	memset(buf, 0, 0x2000);
	
	strcpy(buf, symsrvpath);
	strcat(buf, "symsrv.dll");
	
	//I was getting error at SymFindFileInPath because dbghelp.dll was not able to load symsrv.dll, until I copied sysrv.dll to system32
	if (!PathFileExists("c:\\windows\\system32\\symsrv.dll"))
	{
		res = CopyFileA(buf, "c:\\windows\\system32\\symsrv.dll", TRUE);
		if (!res)
		{
			res = CopyFileA("symsrv.dll", "c:\\windows\\system32\\symsrv.dll", TRUE);
			if (!res)
			{
				printf("Unable to copy symsrv.dll to system32 directory (put symsrv.dll in the same directory as this executable and execute as admin)\r\n");
			}
		}
	}

	//enable debug messages
	DWORD Options = SymGetOptions();
	Options |= SYMOPT_DEBUG;
	SymSetOptions(Options);

	//search for chrome processes
	entry.dwFlags = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry) == TRUE) 
	{
		do
		{
			if (_stricmp(entry.szExeFile, "chrome.exe") == 0)
			{
				HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
				MODULEENTRY32 me32;

				hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, entry.th32ProcessID);
				if (hModuleSnap != INVALID_HANDLE_VALUE)
				{
					me32.dwSize = sizeof(MODULEENTRY32);

					if (Module32First(hModuleSnap, &me32))
					{
						do
						{
							//search for chrome.dll module
							if (!_stricmp(me32.szModule, "chrome.dll"))
							{
								HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);								
								IMAGE_DOS_HEADER IDH;
								IMAGE_NT_HEADERS64 INH;
								
								//read timestamp and size of image (necesary for SymFindFileInPath)
								FILE * f = fopen(me32.szExePath, "rb");
								fread(&IDH, 1, sizeof(IMAGE_DOS_HEADER), f);
								fseek(f, IDH.e_lfanew, 0);
								fread(&INH, 1, sizeof(IMAGE_NT_HEADERS64), f);
								fclose(f);

								printf("chrome.dll found %s at process %x\r\nTrying to load symbols...\r\n", me32.szExePath, entry.th32ProcessID);

								//init
								res = SymInitialize(
									hProcess,
									symbolssrvA,
									FALSE);

								if (res)
								{
									//download pdb for chrome.dll from chromium store: https://chromium-browser-symsrv.commondatastorage.googleapis.com
									res = SymFindFileInPath(hProcess,
										NULL,
										me32.szModule,
										INH.FileHeader.TimeDateStamp,
										INH.OptionalHeader.SizeOfImage,
										0,
										SSRVOPT_DWORD,
										buf,
										NULL,
										NULL);

									if (res)
									{
										//load symbols for chrome.dll
										mbase = SymLoadModule64(
											hProcess,
											NULL,
											me32.szExePath,
											NULL,
											0,
											0);

										memset(&minfo, 0, sizeof(minfo));
										minfo.SizeOfStruct = sizeof(minfo);
										res = SymGetModuleInfo64(hProcess, mbase, &minfo);

										symbol.SizeOfStruct = sizeof(SYMBOL_INFO);

										//get the address of bssl::kTLSProtocolMethod, the table of pointers that malware usually hook
										res = SymFromName(hProcess,
											"bssl::kTLSProtocolMethod",
											&symbol
										);

										if (res)
										{											
											printf("bssl::kTLSProtocolMethod table at %x\r\n", symbol.Address);
											//TODO: check table pointers are not hooked
										}
										else
										{
											printf("Error getting bssl::kTLSProtocolMethod\r\n");
										}

										SymUnloadModule64(hProcess, mbase);
									}
									else
									{
										printf("Error SymFindFileInPath\r\n");
									}

									res = SymCleanup(hProcess);
								}
								else
								{
									printf("Error SymInitialize\r\n");
								}

								CloseHandle(hProcess);
							}

						} while (Module32Next(hModuleSnap, &me32));
					}

					CloseHandle(hModuleSnap);
				}
				res = GetLastError();
			}

		} while (Process32Next(snapshot, &entry) == TRUE);
	}
	CloseHandle(snapshot);
	free(buf);
}
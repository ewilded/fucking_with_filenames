// Being inspired with https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf and the general concept of abusing
// native system calls (e.g NtSetValueKey) by bypassing any implementation limitations imposed by their WinAPI wrappers (e.g. RegSetValueExA) I decided to 
// try this approach with filenames.
// Goal: creation of filenames with nullbytes (or other characters not allowed/mangled by the standard CreateFileA()/CreateFileW() WinAPI calls) for the purpose of:
// - evasion (files not displayed  - or at least badly displayed and thus inaccessible - in explorer/any other tools and interfaces)
// - anti-forensics
// - persistence (e.g. I am curious if it's possible to create a file named foo.dll<NULLBYTE> next to foo.dll - and if so, what will be the result of a 
// LoadLibraryA()/LoadLibraryW() call in such case - whether it would allow us to hijack the DLL loading priority and thus create persistence without overwriting the original file.
// - creation of files with working names (e.g. if there are characters that get ignored at the end of the filename) that would at the same time prevent them from being found, e.g. if .dll<NULLBYTE> would be a working DLL, while at the same time not being picked up by EDR's "DLLFileWritten" function, for instance.

// The program allows to create (I'll implement the remove routines as well if I have to) the following files in the current working subdirectory './test/'.
// 1) a NULL-byte prepended value, \0EVIL1.txt
// 2) a NULL-byte appended value, EVIL2.txt\0
// 3) a NULL-byte-containing value, EVIL\03.txt

// Then I'll try to manually create files EVIL1.txt, EVIL2.txt, EVIL3.txt.

// Successfully compiled & run with Dev CPP on Win10 x64.

#include <windows.h>
#include <string.h>
#include <iostream>

#define HIDDEN_KEY_LENGTH 10


// We are going to have to locally define some of the known data structures and types in order to build the arguments expected by the native function calls
// as well as to be able to dynamically link those native function calls with use of LoadLibraryA() and GetProcAddress().

// Type definition for _UNICODE_STRING structure taken from https://docs.microsoft.com/en-us/windows/desktop/api/subauth/ns-subauth-_unicode_string
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// The NtCreateFile() function we want to abuse to create arbitrary file names - we need these types for our typedef for dynamic linking:
/*
// https://docs.microsoft.com/en-us/windows/desktop/api/winternl/nf-winternl-ntcreatefile
__kernel_entry NTSTATUS NtCreateFile(
  OUT PHANDLE           FileHandle,
  IN ACCESS_MASK        DesiredAccess,
  IN POBJECT_ATTRIBUTES ObjectAttributes,
  OUT PIO_STATUS_BLOCK  IoStatusBlock,
  IN PLARGE_INTEGER     AllocationSize,
  IN ULONG              FileAttributes,
  IN ULONG              ShareAccess,
  IN ULONG              CreateDisposition,
  IN ULONG              CreateOptions,
  IN PVOID              EaBuffer,
  IN ULONG              EaLength
);
*/

// And now some of the data structure types used by the NtCreateFile() function:
// POBJECT_ATTRIBUTES - this is the structure pointing at the filename as well as the root directory handle of the new file
// https://msdn.microsoft.com/en-us/windows/ff557749(v=vs.90)

typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// To obtain a handle to an existing directory, call the CreateFile function with the FILE_FLAG_BACKUP_SEMANTICS flag:
// https://docs.microsoft.com/en-us/windows/desktop/FileIO/obtaining-a-handle-to-a-directory

// Now, the status PIO_STATUS_BLOCK
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_io_status_block
typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID    Pointer;
  } DUMMYUNIONNAME;
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef NTSTATUS (*_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

void createHiddenFile()
{
	
	// 1. Dynamically link the NtCreateFile() function.
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	_NtCreateFile NtCreateFile;
	NtCreateFile=(_NtCreateFile)GetProcAddress(hNtdll,"NtCreateFile");
	
	// 2. Open a handle to the local 'test' subdirectory with CreateFile() with the FILE_FLAG_BACKUP_SEMANTICS flag
	/*
	  HANDLE CreateFileA(
  	  LPCSTR                lpFileName,
  	  DWORD                 dwDesiredAccess,
  	  DWORD                 dwShareMode,
  	  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  	  DWORD                 dwCreationDisposition,
 	  DWORD                 dwFlagsAndAttributes,
	  HANDLE                hTemplateFile
	);
	*/
	LPCSTR dirname="test";
	HANDLE directory = CreateFileA(dirname, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,NULL);
	
	if(directory==INVALID_HANDLE_VALUE)
	{
		printf("Failed opening %s. Exiting.\n",dirname);
		return;
	}
	
	// 3. Preapre the OBJECT_ATTRIBUTES structure
	
	// 4. Delare the PIO_STATUS_BLOCK (it's an output parameter, so we don't have to initialize it)
	
	// 5. Call the function and see the magic happen!
	
	/*
	wchar_t runkeyPath[0x100] = L"hacky";

	wchar_t runkeyPath_trick[0x100] = L"\0\0EVILTEST";  // uncomment for the 'hidden' value

	ValueName.Buffer = runkeyPath_trick;
	ValueName.Length = 2 * HIDDEN_KEY_LENGTH;
	ValueName.MaximumLength = 0;
	//const WCHAR* directory="test";
	
	//LSTATUS openRet = 0;
	//NTSTATUS setRet = 0;
	//HKEY hkResult = NULL;
	//UNICODE_STRING ValueName = { 0 };

	// get the NtSetValueKey Native function address
	if (!(openRet = RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, 0, KEY_SET_VALUE, &hkResult)))
	{
		if (!(setRet = NtSetValueKey(hkResult, &ValueName, 0, REG_SZ, (PVOID)runCmd, wcslen(runCmd) * 2)))
		{
			printf("SUCCESS setting hidden run value!\n");
		}
		else
		{
			printf("FAILURE setting hidden run value! (setRet == 0x%X, GLE() == %d)\n", setRet, GetLastError());
		}
		RegCloseKey(hkResult);
	}
	else

	{
		printf("FAILURE opening RUN key in registry! (openRet == 0x%X, GLE() == %d)\n", openRet, GetLastError());
	}
	*/
}
/*
void deleteHiddenKey()
{
	LSTATUS openRet = 0;
	NTSTATUS delRet = 0;
	HKEY hkResult = NULL;
	UNICODE_STRING ValueName = { 0 };

	// get the NtSetValueKey Native function address
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	_NtDeleteValueKey NtDeleteValueKey;
	NtDeleteValueKey=(_NtDeleteValueKey)GetProcAddress(hNtdll,"NtDeleteValueKey");
	

	wchar_t runkeyPath[0x100] = L"hacky";
	wchar_t runkeyPath_trick[0x100] = L"\0\0EVILTEST";  // uncomment for the 'hidden' value

	ValueName.Buffer = runkeyPath_trick;
	ValueName.Length = 2 * HIDDEN_KEY_LENGTH;
	ValueName.MaximumLength = 0;

	if (!(openRet = RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, 0, KEY_ALL_ACCESS, &hkResult)))
	{
			// OK this won't work without using a Marshalling technique (to be able to call native system functions from managed code)
		if (!(delRet = NtDeleteValueKey(hkResult, &ValueName)))
		{
			printf("SUCCESS removing the fucking nullbyte key run value!\n");
		}
		else
		{
			printf("FAILURE removing the fucking nullbyte run value! (delRet == 0x%X, GetLastError() == %d)\n", delRet, GetLastError());
		}
		RegCloseKey(hkResult);
	}
	else
	{
		printf("FAILURE opening RUN key in registry! (openRet == 0x%X, GLE() == %d)\n", openRet, GetLastError());
	}
}
*/

int main(int argc, char** argv) 
{
	/*
	if(argc!=2)
	{
		printf("Usage: %s create|delete\n",argv[0]);
		return 0;
	}
	if(strcmp(argv[1],"create")==0)
	{
		printf("Trying to create the HKCU\\hacky\\0\\0EVILTEST value...\n");
		wchar_t d[10] = L"TEST";
 		createHiddenKey(d);
	}
	else
	{
		printf("Trying to remove the HKCU\\hacky\\0\\0EVILTEST value...\n");
		deleteHiddenKey();
	}
	*/
	createHiddenFile();
	return 0;	
}

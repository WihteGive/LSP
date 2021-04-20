// freesec.dll.cpp : 定义 DLL 应用程序的入口点。
//

#include"framework.h"
#include <windows.h>

#include<WS2spi.h>
#include<SpOrder.h>
#include<WinUser.h>
#include<locale.h>
#include<rpc.h>
#include<stdio.h>

#include<malloc.h>
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    OutputDebugString(L"DllLoad!");
    MessageBoxA(NULL, "tips", "tips", MB_OK);
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
#include"pch.h"
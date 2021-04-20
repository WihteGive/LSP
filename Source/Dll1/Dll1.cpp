// Dll1.cpp : 定义 DLL 的导出函数。
//

#include "pch.h"
#include "framework.h"
#include "Dll1.h"

#define ShowCurrentLine OutputDebugString(L"__LINE__");
#pragma warning(disable:4996)
#pragma comment(lib,"Ws2_32.lib")

WCHAR exepath[MAX_PATH] = { 0 };
WSPPROC_TABLE trueTable = { 0 };
TCHAR   g_szCurrentApp[MAX_PATH];   // 当前调用本DLL的程序的名称

DLL1_API int GetProvider(LPWSAPROTOCOL_INFOW& pProtoInfo)
{
    //  首次调用，pProtoInfo传入NULL，取得需要的缓冲区长度
    DWORD dwSize = 0;
    int nError = 0;
    if (WSCEnumProtocols(NULL, NULL, &dwSize, &nError) == SOCKET_ERROR)
    {
        if (nError != WSAENOBUFS)
        {
            return 0;
        }
    }
    // 申请足够缓冲区内存。
    pProtoInfo = (LPWSAPROTOCOL_INFOW)GlobalAlloc(GPTR, dwSize);
    if (pProtoInfo == NULL)
    {
        return 0;
    }
    //再次调用WSCEnumProtocols函数
    return WSCEnumProtocols(NULL, pProtoInfo, &dwSize, &nError);
}


int WSPAPI  WSPSend(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno
)
{
    OutputDebugStringW(L"WSPSend Function Load!");
    unsigned long Des_Ip = 0;
    inet_pton(AF_INET, "1.116.94.74", (PVOID)&Des_Ip);
    WCHAR IP_Addr[100] = L"正在连接地址:1.116.94.74";
    MessageBoxW(0, L"Linking", L"Warning!", 0);

    return trueTable.lpWSPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}
int WSPAPI  WSPConnect(
    SOCKET s,
    const struct sockaddr FAR* name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS,
    LPINT lpErrno
)
{
    OutputDebugString(L"Connect!\n");

    PSOCKADDR_IN paddrSrv = (SOCKADDR_IN*)name;
    if (paddrSrv)
    {
        if (paddrSrv->sin_family == AF_INET)
        {
            if (ntohs(paddrSrv->sin_port) == 80 || ntohs(paddrSrv->sin_port)==443)
            {
                GetModuleFileName(NULL, g_szCurrentApp, MAX_PATH);
                OutputDebugString(g_szCurrentApp);

                char szText[MAX_PATH] = { 0 };
                _snprintf_s(szText, sizeof(szText), ("当前端口%d ---IP地址%s Ip地址%d\n"), ntohs(paddrSrv->sin_port), inet_ntoa(paddrSrv->sin_addr), paddrSrv->sin_addr.S_un.S_addr);
                MessageBoxA(0,szText,"Warning!",MB_OK);

                //paddrSrv->sin_addr.S_un.S_addr = inet_addr("1.1.1.1");
                //_snprintf_s(szText, sizeof(szText), ("修改后端口%d ---IP地址%s Ip地址%d\n"), ntohs(paddrSrv->sin_port), inet_ntoa(paddrSrv->sin_addr), paddrSrv->sin_addr.S_un.S_addr);
                //MessageBoxA(0, szText, "Warning!", MB_OK);


            }
        }
    }

    return trueTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);

}



int WSPAPI WSPStartup(
    WORD wVersionRequested,
    LPWSPDATA lpWSPData,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    WSPUPCALLTABLE UpcallTable,
    LPWSPPROC_TABLE lpProcTable
)
/*
    当应用程序通过SOCKET创建socket时会调用系统根据Winsock目录和程序的需要来将对应的传输服务提供者,即
    一个dll加载到目标进程中. 然后调用该dll提供的WSPStartup函数来初始化.初始化的
    目的就是为了通过调用这个函数来获取该这次操作socket的API函数对应的SPI
    这就是windows上写socket时之前必须通过WSAStartup来进行socket初始化的原因
    该函数的lpProcTable 参数是个结构体,保存了所有的SPI函数.也就是可以从这个参数来获取SPI
    所以只需导出这个函数,然后将其他的SPI填写到lpProcTable中,最后返回给程序
    以上都是正常情况下的调用过程. 如果我们让系统加载我们给它提供的dll就可以导出该函数,并
    hook掉lpProcTable中的成员进行监控. 但是我们hook该函数后允许的话应该最后要调用正常的SPI,
    这时参数lpProtocolInfo就能派上用场. 通过该参数可以获取原来的协议的目录id,然后遍历winsock
    目录找到对应的协议的传输服务提供者即一个dll路径,通过加载该dll并调用其中的WSPStartup即可获取
    真正的SPI,然后调用它.最终可以实现监控,修改,拦截等功能
*/
{
    //我们编写的DLL用于协议链中，所以如果是基础协议或分层协议使用则直接返回错误
    if (lpProtocolInfo->ProtocolChain.ChainLen <= 1)
    {
        return WSAEPROVIDERFAILEDINIT;
    }
    WCHAR exename[100] = { 0 };
    wsprintf(exename, L"应用程序: %ls 正在联网,是否允许?", exepath);
    /*if (MessageBoxW(0, exename, L"温馨提示", MB_YESNO | MB_ICONWARNING) == IDNO)
    {
        MessageBoxW(0, L"已拦截", L"提示", 0);
        return WSAEPROVIDERFAILEDINIT;
    }*/
    // 枚举协议，找到下层协议的WSAPROTOCOL_INFOW结构    
    WSAPROTOCOL_INFOW    trueProtocolInfo;    //保存真正的协议结构
    LPWSAPROTOCOL_INFOW pProtoInfo = NULL;
    int allproto = GetProvider(pProtoInfo);
    DWORD trueId = lpProtocolInfo->ProtocolChain.ChainEntries[1];//获取真正的协议目录id
    int i;
    //遍历查找真正的协议结构
    for (i = 0; i < allproto; i++)
    {
        if (pProtoInfo[i].dwCatalogEntryId == trueId)
        {
            memcpy(&trueProtocolInfo, &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
            break;
        }
    }
    //没找到就返回失败
    if (i >= allproto)
    {
        return WSAEPROVIDERFAILEDINIT;
    }
    int nError;
    wchar_t szBaseProviderDll[MAX_PATH];//保存真正dll路径
    int nLen = MAX_PATH;
    // 取得下层提供程序DLL路径
    if (WSCGetProviderPath(&trueProtocolInfo.ProviderId, szBaseProviderDll, &nLen, &nError) == SOCKET_ERROR)
    {
        return WSAEPROVIDERFAILEDINIT;
    }
    //上面的函数执行后路径中会存在环境变量,通过下面展开环境变量
    if (!ExpandEnvironmentStringsW(szBaseProviderDll, szBaseProviderDll, MAX_PATH))
    {
        return WSAEPROVIDERFAILEDINIT;
    }

    // 加载真正dll
    HMODULE hModule = LoadLibraryW(szBaseProviderDll);
    if (hModule == NULL)
    {
        return WSAEPROVIDERFAILEDINIT;
    }

    // 导入真正dll的WSPStartup函数
    LPWSPSTARTUP  pfnWSPStartup = NULL;
    pfnWSPStartup = (LPWSPSTARTUP)GetProcAddress(hModule, "WSPStartup");
    if (pfnWSPStartup == NULL)
    {
        return WSAEPROVIDERFAILEDINIT;
    }

    // 调用下层提供程序的WSPStartup函数以填充SPI地址表
    LPWSAPROTOCOL_INFOW pInfo = lpProtocolInfo;
    //
    if (trueProtocolInfo.ProtocolChain.ChainLen == BASE_PROTOCOL)
    {
        pInfo = &trueProtocolInfo;
    }
    else
    {
        for (int j = 0; j < lpProtocolInfo->ProtocolChain.ChainLen; j++)
        {
            lpProtocolInfo->ProtocolChain.ChainEntries[j]
                = lpProtocolInfo->ProtocolChain.ChainEntries[j + 1];
        }
        lpProtocolInfo->ProtocolChain.ChainLen--;
    }
    //调用真正的WSPStartup, 注意参数,协议结构参数必须是原来我们想劫持的那个协议结构
    int nRet = pfnWSPStartup(wVersionRequested, lpWSPData, pInfo, UpcallTable, lpProcTable);
    if (nRet == ERROR_SUCCESS)
    {
        memcpy(&trueTable, lpProcTable, sizeof(WSPPROC_TABLE)); //保存到trueTable中以便调用
        //进行api替换
        lpProcTable->lpWSPConnect = (LPWSPCONNECT)WSPConnect;
        return nRet;
    }
    else {
        return WSAEPROVIDERFAILEDINIT;
    }
    

}

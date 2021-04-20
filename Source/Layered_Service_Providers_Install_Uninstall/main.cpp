// spi.cpp : 定义控制台应用程序的入口点。
//
#include<WS2spi.h>
#include<SpOrder.h>
#include<WinUser.h>
#include<locale.h>
#include<rpc.h>
#include<stringapiset.h>
#define WIN32_LEAN_AND_MEAN
#include<Windows.h>
#include<stdio.h>
#include<malloc.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Rpcrt4.lib")
GUID layerGuid;
#define layerName L"freesec"  
DWORD findGuid()
{
    //枚举winsock目录中的协议
    LPWSAPROTOCOL_INFOW info;//指向winsock目录中协议
    DWORD size = 0;            //大小
    DWORD num;                //数量
    WSCEnumProtocols(0, 0, &size, 0);
    info = (LPWSAPROTOCOL_INFOW)malloc(size);
    num = WSCEnumProtocols(0, info, &size, 0);
    if (num == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }
    int i;
    for (i = 0; i < num; i++)
    {
        if (lstrcmpW(info[i].szProtocol, layerName) == 0)
        {
            memcpy(&layerGuid, &info[i].ProviderId, sizeof(GUID));
            break;
        }
    }
    free(info);
    if (i == num)//没找到
    {
        return 0;
    }
    return 1;
}
DWORD lspInject(WCHAR* DllPath)
{
    int i;
    //枚举winsock目录中的协议
    LPWSAPROTOCOL_INFOW info;//指向winsock目录中协议
    DWORD size = 0;            //大小
    DWORD num;                //数量
    WSCEnumProtocols(0, 0, &size, 0);
    info = (LPWSAPROTOCOL_INFOW)malloc(size);
    num = WSCEnumProtocols(0, info, &size, 0);
    DWORD trueId;            //存储被安装的提供者的目录id
    if (num == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }

    WCHAR supplier[] = layerName;
    DWORD myId;
    int proto = IPPROTO_TCP; //目标协议

    WSAPROTOCOL_INFOW save = { 0 };    //用于存储指定协议的正常的提供者,最后用来作为分层协议和协议链的模板
    for (int i = 0; i < num; i++)
    {//找符合条件的提供者,但不能是分层协议
        if (info[i].iAddressFamily == AF_INET && info[i].iProtocol == proto && info[i].ProtocolChain.ChainLen != LAYERED_PROTOCOL)
        {
            memcpy(&save, &info[i], sizeof(WSAPROTOCOL_INFOW));    //将原来的基础协议信息保存                                                                
            save.dwServiceFlags1 &= ~XP1_IFS_HANDLES;        //去掉XP1_IFS_HANDLES标志
            trueId = info[i].dwCatalogEntryId;
            break;
        }
    }

    //安装分层协议
    WSAPROTOCOL_INFOW Lpi = { 0 }; //新的分层协议
    memcpy(&Lpi, &save, sizeof(WSAPROTOCOL_INFOW)); //以这个保存的系统已有协议作为模板
    lstrcpyW(Lpi.szProtocol, supplier);    //协议名,其实就是一个代号而已,可以随意起名
    Lpi.ProtocolChain.ChainLen = LAYERED_PROTOCOL;    //设置为分层协议
    Lpi.dwProviderFlags |= PFL_HIDDEN;        //?
    GUID pguid;                    //分层协议的guid
    UuidCreate(&pguid);
    memcpy(&layerGuid, &pguid, sizeof(GUID));
    WORD error = 0;
    if (WSCInstallProvider(&pguid, DllPath, &Lpi, 1, (LPINT)&error) == SOCKET_ERROR)        //安装该分层协议
    {   
        free(info);
        return 0;
    }

    //重新枚举协议以获取分层协议的目录id
    free(info);            //因为添加了一个分层协议,所以需要重新分配内存
    DWORD layerId;        //保存分层协议目录id
    WSCEnumProtocols(0, 0, &size, 0);
    info = (LPWSAPROTOCOL_INFOW)malloc(size);
    num = WSCEnumProtocols(0, info, &size, 0);
    if (num == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }

    for (int i = 0; i < num; i++)        //遍历协议,直到找到刚才新增的分层协议
    {
        if (memcmp(&info[i].ProviderId, &pguid, sizeof(GUID)) == 0)
        {
            layerId = info[i].dwCatalogEntryId;        //获取分层协议目录id
        }
    }

    //安装协议链
    WCHAR chainName[WSAPROTOCOL_LEN + 1];            //其实就是一个名字代号,和分层协议的名字一样
    wsprintf(chainName, L"%ls over %ls", supplier, save.szProtocol);
    lstrcpyW(save.szProtocol, chainName);        //改名字1
    if (save.ProtocolChain.ChainLen == 1) //如果目标协议的正常提供者是基础协议则将其目录id放在协议链的第2个位置
    {
        save.ProtocolChain.ChainEntries[1] = trueId;        //将id写入到该协议链的ChainEntries数组中,这个数组只有当它是协议链时才有意义
    }
    else       //否则就是协议链提供者
    {
        for (int i = save.ProtocolChain.ChainLen; i > 0; i--)//如果是协议链则将该协议链中其他协议往后移,
                                                             //以便将自己的分层协议插入到链首.但是这个数组最大存7个,所以如果原来就占满了,理论上会挤掉最后一个
        {
            save.ProtocolChain.ChainEntries[i] = save.ProtocolChain.ChainEntries[i - 1];
        }
    }

    save.ProtocolChain.ChainEntries[0] = layerId;
    save.ProtocolChain.ChainLen++;

    //获取guid,安装协议链
    GUID providerChainGuid;
    UuidCreate(&providerChainGuid);
    if (WSCInstallProvider(&providerChainGuid, DllPath, &save, 1, 0) == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }

    //重新枚举协议
    free(info);
    WSCEnumProtocols(0, 0, &size, 0);
    info = (LPWSAPROTOCOL_INFOW)malloc(size);
    num = WSCEnumProtocols(0, info, &size, 0);
    if (num == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }
    //遍历获取我们的协议链的目录id
    DWORD* chainId = (DWORD*)malloc(num * sizeof(DWORD)); //这个是协议链的目录id数组,把我们的协议链id
                                                          //放在最前面,系统原来的按顺序放后面
    DWORD cindex = 0;
    for (int i = 0; i < num; i++)
    {
        if ((info[i].ProtocolChain.ChainLen > 1) && (info[i].ProtocolChain.ChainEntries[0] == layerId))
        {
            chainId[cindex] = info[i].dwCatalogEntryId;
            cindex++;
        }
    }
    for (int i = 0; i < num; i++)
    {
        if ((info[i].ProtocolChain.ChainLen <= 1) || (info[i].ProtocolChain.ChainEntries[0] != layerId))
        {
            chainId[cindex] = info[i].dwCatalogEntryId;
            cindex++;
        }
    }

    if (WSCWriteProviderOrder(chainId, cindex) != 0)
    {
        free(info);
        free(chainId);
        return 0;
    }


    free(info);
    free(chainId);
    return 1;


}

DWORD uninstall()
{
    if (findGuid() == 0)
    {
        return 0;
    }
    //枚举winsock目录中的协议
    LPWSAPROTOCOL_INFOW info;//指向winsock目录中协议
    DWORD size = 0;            //大小
    DWORD num;                //数量
    DWORD Id;
    DWORD result;
    int cc;         //作为错误码,下面2个函数的错误码地址必须提供,否则会调用失败
    WSCEnumProtocols(0, 0, &size, 0);
    info = (LPWSAPROTOCOL_INFOW)malloc(size);
    num = WSCEnumProtocols(0, info, &size, 0);
    if (num == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }
    int i = 0;

    for (i = 0; i < num; i++)
    {
        if (memcmp(&layerGuid, &info[i].ProviderId, sizeof(GUID)) == 0)
        {
            Id = info[i].dwCatalogEntryId;
        }
    }
    if (i <= num)
    {
        for (i = 0; i < num; i++)
        {
            if ((info[i].ProtocolChain.ChainLen > 1) && (info[i].ProtocolChain.ChainEntries[0] == Id))
            {

                if ((result = WSCDeinstallProvider(&info[i].ProviderId, &cc)) == SOCKET_ERROR)
                {

                    free(info);
                    return 0;
                }
                break;
            }
        }
        free(info);
        if ((result = WSCDeinstallProvider(&layerGuid, &cc)) == SOCKET_ERROR)
        {
            return 0;
        }
    }
    else
    {
        free(info);
        return 0;
    }return 1;
}
int main(int argc, char** argv)
{

    WCHAR dllpath_debug[] = L"C:\\Users\\ASUS\\source\\repos\\Test_C_2\\Debug\\Dll1.dll";//指定你的dll文件
    WCHAR dllpath_release[] = L"C:\\Users\\ASUS\\source\\repos\\Test_C_2\\Release\\Dll1.dll";//指定你的dll文件
    if (argc < 1) {
        printf("usage:LspInject (install/uninstall) dllpath\n");
        return 0;
    }
    if (!strcmp(argv[1],"install")) {
        if (argc < 3) {
            printf("usage:LspInject (install/uninstall) dllpath\n");
            return 0;
        }
        else {
            WCHAR* Buffer = NULL;
            DWORD BufferSize = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (argv[2]), -1, 0,0);
            Buffer = new WCHAR[BufferSize];
            BufferSize = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (argv[2]), -1, Buffer, BufferSize);
            if (!lspInject(Buffer)) {
                printf("Sorry Failed to inject!\n");
            }
        }
        
    }
    else if(!strcmp(argv[1],"uninstall")) {
        uninstall();
    }

}
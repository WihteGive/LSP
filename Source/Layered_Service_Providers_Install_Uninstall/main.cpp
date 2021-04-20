// spi.cpp : �������̨Ӧ�ó������ڵ㡣
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
    //ö��winsockĿ¼�е�Э��
    LPWSAPROTOCOL_INFOW info;//ָ��winsockĿ¼��Э��
    DWORD size = 0;            //��С
    DWORD num;                //����
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
    if (i == num)//û�ҵ�
    {
        return 0;
    }
    return 1;
}
DWORD lspInject(WCHAR* DllPath)
{
    int i;
    //ö��winsockĿ¼�е�Э��
    LPWSAPROTOCOL_INFOW info;//ָ��winsockĿ¼��Э��
    DWORD size = 0;            //��С
    DWORD num;                //����
    WSCEnumProtocols(0, 0, &size, 0);
    info = (LPWSAPROTOCOL_INFOW)malloc(size);
    num = WSCEnumProtocols(0, info, &size, 0);
    DWORD trueId;            //�洢����װ���ṩ�ߵ�Ŀ¼id
    if (num == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }

    WCHAR supplier[] = layerName;
    DWORD myId;
    int proto = IPPROTO_TCP; //Ŀ��Э��

    WSAPROTOCOL_INFOW save = { 0 };    //���ڴ洢ָ��Э����������ṩ��,���������Ϊ�ֲ�Э���Э������ģ��
    for (int i = 0; i < num; i++)
    {//�ҷ����������ṩ��,�������Ƿֲ�Э��
        if (info[i].iAddressFamily == AF_INET && info[i].iProtocol == proto && info[i].ProtocolChain.ChainLen != LAYERED_PROTOCOL)
        {
            memcpy(&save, &info[i], sizeof(WSAPROTOCOL_INFOW));    //��ԭ���Ļ���Э����Ϣ����                                                                
            save.dwServiceFlags1 &= ~XP1_IFS_HANDLES;        //ȥ��XP1_IFS_HANDLES��־
            trueId = info[i].dwCatalogEntryId;
            break;
        }
    }

    //��װ�ֲ�Э��
    WSAPROTOCOL_INFOW Lpi = { 0 }; //�µķֲ�Э��
    memcpy(&Lpi, &save, sizeof(WSAPROTOCOL_INFOW)); //����������ϵͳ����Э����Ϊģ��
    lstrcpyW(Lpi.szProtocol, supplier);    //Э����,��ʵ����һ�����Ŷ���,������������
    Lpi.ProtocolChain.ChainLen = LAYERED_PROTOCOL;    //����Ϊ�ֲ�Э��
    Lpi.dwProviderFlags |= PFL_HIDDEN;        //?
    GUID pguid;                    //�ֲ�Э���guid
    UuidCreate(&pguid);
    memcpy(&layerGuid, &pguid, sizeof(GUID));
    WORD error = 0;
    if (WSCInstallProvider(&pguid, DllPath, &Lpi, 1, (LPINT)&error) == SOCKET_ERROR)        //��װ�÷ֲ�Э��
    {   
        free(info);
        return 0;
    }

    //����ö��Э���Ի�ȡ�ֲ�Э���Ŀ¼id
    free(info);            //��Ϊ�����һ���ֲ�Э��,������Ҫ���·����ڴ�
    DWORD layerId;        //����ֲ�Э��Ŀ¼id
    WSCEnumProtocols(0, 0, &size, 0);
    info = (LPWSAPROTOCOL_INFOW)malloc(size);
    num = WSCEnumProtocols(0, info, &size, 0);
    if (num == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }

    for (int i = 0; i < num; i++)        //����Э��,ֱ���ҵ��ղ������ķֲ�Э��
    {
        if (memcmp(&info[i].ProviderId, &pguid, sizeof(GUID)) == 0)
        {
            layerId = info[i].dwCatalogEntryId;        //��ȡ�ֲ�Э��Ŀ¼id
        }
    }

    //��װЭ����
    WCHAR chainName[WSAPROTOCOL_LEN + 1];            //��ʵ����һ�����ִ���,�ͷֲ�Э�������һ��
    wsprintf(chainName, L"%ls over %ls", supplier, save.szProtocol);
    lstrcpyW(save.szProtocol, chainName);        //������1
    if (save.ProtocolChain.ChainLen == 1) //���Ŀ��Э��������ṩ���ǻ���Э������Ŀ¼id����Э�����ĵ�2��λ��
    {
        save.ProtocolChain.ChainEntries[1] = trueId;        //��idд�뵽��Э������ChainEntries������,�������ֻ�е�����Э����ʱ��������
    }
    else       //�������Э�����ṩ��
    {
        for (int i = save.ProtocolChain.ChainLen; i > 0; i--)//�����Э�����򽫸�Э����������Э��������,
                                                             //�Ա㽫�Լ��ķֲ�Э����뵽����.���������������7��,�������ԭ����ռ����,�����ϻἷ�����һ��
        {
            save.ProtocolChain.ChainEntries[i] = save.ProtocolChain.ChainEntries[i - 1];
        }
    }

    save.ProtocolChain.ChainEntries[0] = layerId;
    save.ProtocolChain.ChainLen++;

    //��ȡguid,��װЭ����
    GUID providerChainGuid;
    UuidCreate(&providerChainGuid);
    if (WSCInstallProvider(&providerChainGuid, DllPath, &save, 1, 0) == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }

    //����ö��Э��
    free(info);
    WSCEnumProtocols(0, 0, &size, 0);
    info = (LPWSAPROTOCOL_INFOW)malloc(size);
    num = WSCEnumProtocols(0, info, &size, 0);
    if (num == SOCKET_ERROR)
    {
        free(info);
        return 0;
    }
    //������ȡ���ǵ�Э������Ŀ¼id
    DWORD* chainId = (DWORD*)malloc(num * sizeof(DWORD)); //�����Э������Ŀ¼id����,�����ǵ�Э����id
                                                          //������ǰ��,ϵͳԭ���İ�˳��ź���
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
    //ö��winsockĿ¼�е�Э��
    LPWSAPROTOCOL_INFOW info;//ָ��winsockĿ¼��Э��
    DWORD size = 0;            //��С
    DWORD num;                //����
    DWORD Id;
    DWORD result;
    int cc;         //��Ϊ������,����2�������Ĵ������ַ�����ṩ,��������ʧ��
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

    WCHAR dllpath_debug[] = L"C:\\Users\\ASUS\\source\\repos\\Test_C_2\\Debug\\Dll1.dll";//ָ�����dll�ļ�
    WCHAR dllpath_release[] = L"C:\\Users\\ASUS\\source\\repos\\Test_C_2\\Release\\Dll1.dll";//ָ�����dll�ļ�
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
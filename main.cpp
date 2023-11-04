#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include <Windows.h>

bool LaunchUsingExplorer(const std::wstring& name, std::string& errorMsg);

bool GetMainProcessToken(HANDLE& token, std::string& errorMsg);
bool SetPrivilege(HANDLE token, const std::wstring& lpszPrivilege, bool bEnablePrivilege, std::string& errorMsg);
bool SetTokenIntegrityLevel(HANDLE token, const std::string& sid, std::string& errorMsg);
bool DuplicateToken(HANDLE token, HANDLE& dupToken, std::string& errorMsg);
bool CreateRestrictedToken(HANDLE token, HANDLE& restrictedToken, std::string& errorMsg);

bool LaunchAsUser(HANDLE token, const std::wstring& name, std::string& errorMsg, DWORD& processId);

bool GetProcessId(const std::wstring& processName, DWORD& processID, std::string& errorMsg);
bool IsRunningElevated(bool& isElevated, HANDLE token);
bool IsRunningElevated(bool& isElevated, DWORD processId);
void PrintTokenPrivilege(HANDLE token);
void GetErrorDescription(int rawError, std::string& desc, int& code);

#define explorer
//#define token

int main()
{
#ifdef _DEBUG
    int flag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
    flag |= _CRTDBG_LEAK_CHECK_DF; // Turn on leak-checking bit
    _CrtSetDbgFlag(flag);
    //_CrtSetBreakAlloc(2794); // Comment or un-comment on need basis
#endif

    std::string errorMsg;
    bool isElevated = false;

#if defined(explorer)
    bool ret = LaunchUsingExplorer(L"C:\\Windows\\notepad.exe", errorMsg);
    if (!ret)
    {
        std::cout << errorMsg << "\n";
        return -1;
    }

#elif defined(token)
    HANDLE currentToken, dupToken;
    bool ret = GetMainProcessToken(currentToken, errorMsg);
    if (!ret)
    {
        std::cout << errorMsg;
        return -1;
    }

    ret = DuplicateToken(currentToken, dupToken, errorMsg);
    if (!ret)
    {
        std::cout << errorMsg;
        CloseHandle(currentToken);
        return -1;
    }

#if defined(set_token)
    // Low level; see table for integrity level string names.
    std::string requestedSid = "S-1-16-4096";
    SetTokenIntegrityLevel(dupToken, requestedSid, errorMsg);
#else
    CreateRestrictedToken(currentToken, dupToken, errorMsg);
#endif

    ret = IsRunningElevated(isElevated, dupToken);
    if (!ret)
    {
        std::cout << errorMsg;
        return -1;
    }
    if (isElevated)
    {
        std::cout << "Token still elevated";
        return -1;
    }

    LaunchAsUser(dupToken, L"C:\\Windows\\Notepad.exe", errorMsg, processId);

    CloseHandle(dupToken);
    CloseHandle(currentToken);

#endif

    // There is a chance the process is not launched yet.
    std::chrono::seconds timespan(1);
    std::this_thread::sleep_for(timespan);

    DWORD processId = 0;
    ret = GetProcessId(L"notepad.exe", processId, errorMsg);
    if (!ret)
    {
        std::cout << errorMsg << "\n";
    }
    ret = IsRunningElevated(isElevated, processId);
    if (!ret)
    {
        std::cout << errorMsg << "\n";
    }
    if (!isElevated)
    {
        std::cout << "We succeed in launching in non elevated mode.\n";
    }
    else
    {
        std::cout << "We failed in launching in non elevated mode.\n";
    }

    system("pause");

    // We're done with the test, kill the process.
    HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, false, processId);
    TerminateProcess(processHandle, 1);
    CloseHandle(processHandle);

    return 0;
}

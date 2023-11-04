#include <string>

#include <Windows.h>
#include <Sddl.h>

// Get the current process' security token as a starting point, then modify a duplicate so that it runs with a fixed integrity level.
bool GetMainProcessToken(HANDLE& token, std::string& errorMsg)
{
    //DWORD desiredAccess = TOKEN_ALL_ACCESS;
    //DWORD desiredAccess = TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY;
    DWORD desiredAccess = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY;
    BOOL ret = OpenProcessToken(GetCurrentProcess(), desiredAccess, &token);
    if (!ret)
    {
        errorMsg = "OpenProcessToken error: " + std::to_string(GetLastError());
    }
    return ret;
}

bool SetPrivilege(HANDLE token, const std::wstring& lpszPrivilege, bool bEnablePrivilege, std::string& errorMsg)
{
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;

    // Lookup lpszPrivilege on local system.
    if (!LookupPrivilegeValue(NULL, lpszPrivilege.c_str(), &luid))
    {
        errorMsg = "LookupPrivilegeValue error: " + std::to_string(GetLastError());
        return false;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
    {
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tokenPrivileges.Privileges[0].Attributes = 0;
    }

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        errorMsg = "AdjustTokenPrivileges error: " + std::to_string(GetLastError());
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        errorMsg = "The token does not have the specified privilege.";
        return false;
    }

    return true;
}

// Probably does not work anymore.
bool SetTokenIntegrityLevel(HANDLE token, const std::string& sid, std::string& errorMsg)
{
    // Convert the string SID to a SID *, then adjust the token's privileges.
    PSID psd = NULL;
    if (!ConvertStringSidToSidA(sid.c_str(), &psd))
    {
        errorMsg = "ConvertStringSidToSid error: " + std::to_string(GetLastError());
        return false;
    }
    TOKEN_MANDATORY_LABEL tml;
    ZeroMemory(&tml, sizeof(tml));
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = psd;

    BOOL ret = SetTokenInformation(token, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(psd));
    if (!ret)
    {
        errorMsg = "SetTokenInformation error: " + std::to_string(GetLastError());
    }
    LocalFree(psd);
    return ret;
}

bool DuplicateToken(HANDLE token, HANDLE& dupToken, std::string& errorMsg)
{
    BOOL ret = DuplicateTokenEx(token, 0, NULL, SecurityImpersonation, TokenPrimary, &dupToken);
    if (!ret)
    {
        errorMsg = "DuplicateTokenEx error: " + std::to_string(GetLastError());
    }
    return ret;
}

bool CreateRestrictedToken(HANDLE token, HANDLE& restrictedToken, std::string& errorMsg)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    SID_AND_ATTRIBUTES dropSids[2];
    ZeroMemory(&dropSids, sizeof(dropSids));

    BOOL ret = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &dropSids[0].Sid);
    if (!ret)
    {
        errorMsg = "AllocateAndInitializeSid(admins) error: " + std::to_string(GetLastError());
        FreeSid(dropSids[0].Sid);
        FreeSid(dropSids[1].Sid);
        return false;
    }

    ret = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_POWER_USERS, 0, 0, 0, 0, 0, 0, &dropSids[0].Sid);
    if (!ret)
    {
        errorMsg = "AllocateAndInitializeSid(power user) error: " + std::to_string(GetLastError());
        FreeSid(dropSids[0].Sid);
        FreeSid(dropSids[1].Sid);
        return false;
    }

    ret = CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &restrictedToken);
    if (!ret)
    {
        errorMsg = "CreateRestrictedToken error: " + std::to_string(GetLastError());
    }

    FreeSid(dropSids[0].Sid);
    FreeSid(dropSids[1].Sid);
    return ret;
}

bool LaunchAsUser(HANDLE token, const std::wstring& name, std::string& errorMsg, DWORD& processId)
{
    PROCESS_INFORMATION processInfo;
    STARTUPINFO startupInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    BOOL ret = CreateProcessAsUser(token, name.c_str(), NULL, NULL, NULL, FALSE, CREATE_NEW_PROCESS_GROUP, NULL, NULL, &startupInfo, &processInfo);
    if (!ret)
    {
        errorMsg = "CreateProcessAsUser failed with " + std::to_string(GetLastError());
    }
    else
    {
        processId = processInfo.dwProcessId;
    }

    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    return ret;
}

#ifdef DOES_NOT_WORK
// This function DOES NOT WORK. Elevation.TokenIsElevated cannot be set, only use for query.
void SetRunningAsNonAdmin(HANDLE token)
{
    TOKEN_ELEVATION Elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    Elevation.TokenIsElevated = FALSE;
    SetTokenInformation(token, TokenElevation, &Elevation, cbSize);
}
#endif

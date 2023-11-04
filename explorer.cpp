#include <string>
#include <vector>

#include <shlobj.h>
#include <Windows.h>

namespace
{
    bool GetSystemRootDir(std::wstring& sysRootDir, std::string& errorMsg)
    {
        std::vector<wchar_t> buffer(MAX_PATH, 0);
        BOOL isWoW64Process = FALSE;
        BOOL ret = ::IsWow64Process(GetCurrentProcess(), &isWoW64Process);
        if (!ret)
        {
            errorMsg = "IsWow64Process failed with " + std::to_string(GetLastError());
            return false;
        }

        if (isWoW64Process)
        {
            std::wstring variableName = L"SystemRoot";
            DWORD size = ::GetEnvironmentVariable(variableName.c_str(), &buffer.front(), static_cast<DWORD>(buffer.size()));

            if (size > MAX_PATH)
            {
                buffer.resize(size);
                size = ::GetEnvironmentVariable(variableName.c_str(), &buffer.front(), static_cast<DWORD>(buffer.size()));
            }

            if (size == 0)
            {
                errorMsg = "GetEnvironmentVariable failed with " + std::to_string(GetLastError());
                return false;
            }
        }
        else
        {
            // https://docs.microsoft.com/en-us/windows/win32/shell/csidl
            HRESULT result = ::SHGetFolderPath(NULL, CSIDL_WINDOWS, NULL, SHGFP_TYPE_CURRENT, &buffer.front());
            if (FAILED(result))
            {
                errorMsg = "SHGetFolderPath failed with " + std::to_string(result);
                return false;
            }
        }

        sysRootDir = std::wstring(&buffer.front());
        return true;
    }
}

bool LaunchUsingExplorer(const std::wstring& name, std::string& errorMsg)
{
    std::wstring sysRootDir;
    bool ret = GetSystemRootDir(sysRootDir, errorMsg);
    if (!ret)
    {
        return false;
    }
    const std::wstring explorerPath = sysRootDir + L"\\explorer.exe";
    std::wstring command = L" \"" + name + L"\"";

    PROCESS_INFORMATION processInfo;
    STARTUPINFO startupInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    ret = CreateProcess(explorerPath.c_str(), &command[0], NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfo, &processInfo) == TRUE;
    if (!ret)
    {
        errorMsg = "CreateProcessAsUser failed with " + std::to_string(GetLastError());
    }

    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    return ret;
}

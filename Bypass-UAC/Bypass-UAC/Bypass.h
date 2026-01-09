#pragma once

#pragma warning(disable: 4005)
#pragma warning(disable: 4055)
#pragma warning(disable: 4152)
#pragma warning(disable: 4201)
#pragma warning(disable: 6102) 
#pragma warning(disable: 6258)
#pragma warning(disable: 6320)
#pragma warning(disable: 6255 6263)
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <ntstatus.h>
#include <CommCtrl.h>
#include <shlobj.h>
#include <AccCtrl.h>

extern void Bypass();
extern BOOL IsElevated();
#pragma comment(lib, "Version.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
extern BOOL GetOSVersion();
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Impersonation
{
	internal class Impersonate
	{
		public static class Impersonation
		{

			private const uint PROCESS_QUERY_INFORMATION = 0x0400;
			private const uint TOKEN_DUPLICATE = 0x0002;
			private const uint TOKEN_QUERY = 0x0008;
			private const int SecurityImpersonation = 2;

			[DllImport("kernel32.dll", SetLastError = true)]
			private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

			[DllImport("advapi32.dll", SetLastError = true)]
			private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

			[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
			private static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

			[DllImport("advapi32.dll", SetLastError = true)]
			private static extern bool SetThreadToken(IntPtr ThreadHandle, IntPtr TokenHandle);

			[DllImport("kernel32.dll", SetLastError = true)]
			private static extern bool CloseHandle(IntPtr hObject);

			public static bool InjectToken(string processName)
			{
				if (Privilege.EnableSeDebugPrivilege() == false)
				{
					return false;
				}
				Process[] processes = Process.GetProcessesByName(processName);
				if (processes.Length == 0)
				{
					return false;
				}

				int targetPid = processes[0].Id;
				IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, targetPid);
				if (hProcess == IntPtr.Zero)
				{
					return false;
				}

				IntPtr hToken = IntPtr.Zero;
				IntPtr hDuplicateToken = IntPtr.Zero;

				try
				{
					if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken))
						return false;

					if (!DuplicateToken(hToken, SecurityImpersonation, out hDuplicateToken))
						return false;

					if (!SetThreadToken(IntPtr.Zero, hDuplicateToken))
					{
						return false;
					}

					return true;
				}
				catch
				{
					return false;
				}
				finally
				{
					if (hDuplicateToken != IntPtr.Zero) CloseHandle(hDuplicateToken);
					if (hToken != IntPtr.Zero) CloseHandle(hToken);
					if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
				}
			}
			public static bool RevertToken()
			{
				if (!SetThreadToken(IntPtr.Zero, IntPtr.Zero))
				{
					return false;
				}

				return true;
			}
		}
	}
}

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Impersonation
{
	internal class Privilege
	{
		private const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
		private const uint TOKEN_QUERY = 0x08;
		private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

		[StructLayout(LayoutKind.Sequential)]
		struct LUID
		{
			public uint LowPart;
			public int HighPart;
		}

		[StructLayout(LayoutKind.Sequential)]
		struct TOKEN_PRIVILEGES
		{
			public uint PrivilegeCount;
			public LUID Luid;
			public uint Attributes;
		}

		[DllImport("advapi32.dll", SetLastError = true)]
		static extern bool OpenProcessToken(
			IntPtr ProcessHandle,
			uint DesiredAccess,
			out IntPtr TokenHandle);

		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		static extern bool LookupPrivilegeValue(
			string lpSystemName,
			string lpName,
			out LUID lpLuid);

		[DllImport("advapi32.dll", SetLastError = true)]
		static extern bool AdjustTokenPrivileges(
			IntPtr TokenHandle,
			bool DisableAllPrivileges,
			ref TOKEN_PRIVILEGES NewState,
			int BufferLength,
			IntPtr PreviousState,
			IntPtr ReturnLength);

		[DllImport("kernel32.dll")]
		static extern bool CloseHandle(IntPtr hObject);

		public static bool EnableSeDebugPrivilege()
		{
			if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
				out IntPtr token))
			{
				throw new Win32Exception(Marshal.GetLastWin32Error());
			}

			try
			{
				if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out LUID luid))
				{
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}

				TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
				{
					PrivilegeCount = 1,
					Luid = luid,
					Attributes = SE_PRIVILEGE_ENABLED
				};

				if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
				{
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}

				// ERROR_SUCCESS(0)이어야 실제로 활성화됨
				return Marshal.GetLastWin32Error() == 0;
			}
			finally
			{
				CloseHandle(token);
			}
		}
	}
}

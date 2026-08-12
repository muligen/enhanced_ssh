using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AgentSsh.WindowsJobSupervisor;

internal static class Program
{
    // OpenSSH only propagates an 8-bit remote exit status. A Win32-only value
    // outside that range lets the Node parent distinguish supervisor failure.
    private const int SupervisorFailureExitCode = unchecked((int)0xe0535301u);

    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Fail("this supervisor can only run on Windows");
        }

        int argumentIndex = 0;
        ChildInputMode inputMode = args.Length == 0
            ? ChildInputMode.Null
            : args[argumentIndex] switch
            {
                "--stdin-payload" => ChildInputMode.Payload,
                "--stdin-stream" => ChildInputMode.Stream,
                _ => ChildInputMode.Null,
            };
        if (inputMode != ChildInputMode.Null)
        {
            argumentIndex++;
        }

        int? parentProcessId = null;
        if (argumentIndex < args.Length && args[argumentIndex] == "--parent-pid")
        {
            if (
                argumentIndex + 1 >= args.Length ||
                !int.TryParse(
                    args[argumentIndex + 1],
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out int parsedParentProcessId) ||
                parsedParentProcessId <= 0)
            {
                return Fail("--parent-pid must be a positive process ID");
            }
            parentProcessId = parsedParentProcessId;
            argumentIndex += 2;
        }
        if (inputMode == ChildInputMode.Stream && parentProcessId is null)
        {
            return Fail("--stdin-stream requires --parent-pid");
        }
        if (args.Length < argumentIndex + 2 || args[argumentIndex] != "--")
        {
            return Fail("usage: windows-job-supervisor [--stdin-payload|--stdin-stream] [--parent-pid PID] -- <absolute-executable> [argument ...]");
        }

        string executable = args[argumentIndex + 1];
        if (!Path.IsPathFullyQualified(executable))
        {
            return Fail("the child executable path must be absolute");
        }

        if (executable.IndexOf('\0') >= 0 || !File.Exists(executable))
        {
            return Fail($"the child executable does not exist: {executable}");
        }

        try
        {
            return WindowsJob.Run(
                executable,
                args.AsSpan(argumentIndex + 2),
                inputMode,
                parentProcessId);
        }
        catch (Exception exception) when (
            exception is Win32Exception or InvalidOperationException or ArgumentException or IOException)
        {
            return Fail(exception.Message);
        }
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"windows-job-supervisor: {message}");
        return SupervisorFailureExitCode;
    }
}

internal enum ChildInputMode
{
    Null,
    Payload,
    Stream,
}

internal static class WindowsJob
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint Infinite = 0xffffffff;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint ProcThreadAttributeHandleList = 0x00020002;
    private const uint ProcThreadAttributeJobList = 0x0002000d;
    private const uint StartupUseStdHandles = 0x00000100;
    private const uint StillActive = 259;
    private const uint Synchronize = 0x00100000;
    private const uint CancelledExitCode = 130;
    private const int StdOutputHandle = -11;
    private const int StdErrorHandle = -12;
    private const int MaxChildStandardInputBytes = 1024 * 1024;
    private const int MaxBufferedStreamInputBytes = 4 * 1024 * 1024;

    public static int Run(
        string executable,
        ReadOnlySpan<string> arguments,
        ChildInputMode inputMode,
        int? parentProcessId)
    {
        nint jobHandle = 0;
        nint processHandle = 0;
        nint threadHandle = 0;
        nint childStdInput = 0;
        nint childStdInputWrite = 0;
        nint childStdOutput = 0;
        nint childStdError = 0;
        nint attributeList = 0;
        nint handleList = 0;
        nint jobList = 0;
        nint parentProcessHandle = 0;
        bool attributeListWasInitialized = false;
        bool childWasCreated = false;
        bool childWasAssigned = false;
        Stream? parentInput = null;

        try
        {
            if (parentProcessId is int requiredParentProcessId)
            {
                parentProcessHandle = NativeMethods.OpenProcess(
                    Synchronize,
                    false,
                    checked((uint)requiredParentProcessId));
                ThrowIfInvalid(parentProcessHandle, "OpenProcess(parent)");
            }

            jobHandle = NativeMethods.CreateJobObjectW(0, null);
            ThrowIfInvalid(jobHandle, "CreateJobObjectW");

            var limits = new JobObjectExtendedLimitInformation
            {
                BasicLimitInformation = new JobObjectBasicLimitInformation
                {
                    LimitFlags = JobObjectLimitKillOnJobClose,
                },
            };

            if (!NativeMethods.SetInformationJobObject(
                    jobHandle,
                    JobObjectInformationClass.ExtendedLimitInformation,
                    ref limits,
                    (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
            {
                throw LastWin32("SetInformationJobObject");
            }

            if (inputMode != ChildInputMode.Null)
            {
                CreateInheritableInputPipe(out childStdInput, out childStdInputWrite);
            }
            else
            {
                childStdInput = CreateInheritableNullInput();
            }
            childStdOutput = DuplicateInheritableStandardHandle(StdOutputHandle, "stdout");
            childStdError = DuplicateInheritableStandardHandle(StdErrorHandle, "stderr");

            var startupInfo = new StartupInfoEx
            {
                StartupInfo = new StartupInfo
                {
                    Cb = Marshal.SizeOf<StartupInfoEx>(),
                    Flags = StartupUseStdHandles,
                    StandardInput = childStdInput,
                    StandardOutput = childStdOutput,
                    StandardError = childStdError,
                },
            };

            nuint attributeListSize = 0;
            _ = NativeMethods.InitializeProcThreadAttributeList(0, 2, 0, ref attributeListSize);
            if (attributeListSize == 0)
            {
                throw LastWin32("InitializeProcThreadAttributeList(size)");
            }

            attributeList = Marshal.AllocHGlobal(checked((nint)attributeListSize));
            if (!NativeMethods.InitializeProcThreadAttributeList(
                    attributeList,
                    2,
                    0,
                    ref attributeListSize))
            {
                throw LastWin32("InitializeProcThreadAttributeList");
            }

            attributeListWasInitialized = true;
            startupInfo.AttributeList = attributeList;
            handleList = Marshal.AllocHGlobal(3 * nint.Size);
            Marshal.WriteIntPtr(handleList, 0, childStdInput);
            Marshal.WriteIntPtr(handleList, nint.Size, childStdOutput);
            Marshal.WriteIntPtr(handleList, 2 * nint.Size, childStdError);

            if (!NativeMethods.UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    ProcThreadAttributeHandleList,
                    handleList,
                    checked((nuint)(3 * nint.Size)),
                    0,
                    0))
            {
                throw LastWin32("UpdateProcThreadAttribute(HANDLE_LIST)");
            }

            jobList = Marshal.AllocHGlobal(nint.Size);
            Marshal.WriteIntPtr(jobList, jobHandle);
            if (!NativeMethods.UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    ProcThreadAttributeJobList,
                    jobList,
                    checked((nuint)nint.Size),
                    0,
                    0))
            {
                throw LastWin32("UpdateProcThreadAttribute(JOB_LIST)");
            }

            var commandLine = new StringBuilder(BuildCommandLine(executable, arguments));
            if (!NativeMethods.CreateProcessW(
                    executable,
                    commandLine,
                    0,
                    0,
                    true,
                    CreateSuspended | CreateNoWindow | ExtendedStartupInfoPresent,
                    0,
                    null,
                    ref startupInfo,
                    out ProcessInformation processInformation))
            {
                throw LastWin32("CreateProcessW");
            }

            childWasCreated = true;
            // JOB_LIST makes membership part of process creation, so there is no
            // parent-crash window containing an unassigned suspended child.
            childWasAssigned = true;
            processHandle = processInformation.Process;
            threadHandle = processInformation.Thread;
            if (parentProcessHandle != 0)
            {
                StartParentProcessMonitor(jobHandle, parentProcessHandle);
                parentProcessHandle = 0;
            }
            if (inputMode != ChildInputMode.Null)
            {
                // The child owns the inherited read handle after CreateProcessW.
                CloseIfValid(childStdInput);
                childStdInput = 0;
            }
            Console.Error.Write("agent-ssh-job-supervisor-ready-v1\n");
            Console.Error.Flush();

            if (NativeMethods.ResumeThread(threadHandle) == uint.MaxValue)
            {
                throw LastWin32("ResumeThread");
            }

            if (inputMode == ChildInputMode.Payload)
            {
                parentInput = Console.OpenStandardInput();
                nint ownedWriteHandle = childStdInputWrite;
                childStdInputWrite = 0;
                ForwardInputPayload(parentInput, ownedWriteHandle);
            }
            if (inputMode == ChildInputMode.Stream)
            {
                parentInput = Console.OpenStandardInput();
                nint ownedWriteHandle = childStdInputWrite;
                childStdInputWrite = 0;
                StartInputStreamForwarder(jobHandle, parentInput, ownedWriteHandle);
                parentInput = null;
            }
            else
            {
                Stream livenessInput = parentInput ?? Console.OpenStandardInput();
                parentInput = null;
                StartParentLivenessMonitor(jobHandle, livenessInput);
            }

            uint waitResult = NativeMethods.WaitForSingleObject(processHandle, Infinite);
            if (waitResult != 0)
            {
                throw LastWin32("WaitForSingleObject");
            }

            if (!NativeMethods.GetExitCodeProcess(processHandle, out uint exitCode))
            {
                throw LastWin32("GetExitCodeProcess");
            }

            if (exitCode == StillActive)
            {
                throw new InvalidOperationException("the child remained active after its process handle was signaled");
            }

            return unchecked((int)exitCode);
        }
        finally
        {
            if (childWasCreated && !childWasAssigned && processHandle != 0)
            {
                _ = NativeMethods.TerminateProcess(processHandle, CancelledExitCode);
            }
            else if (childWasAssigned && jobHandle != 0 && processHandle != 0 && IsProcessActive(processHandle))
            {
                _ = NativeMethods.TerminateJobObject(jobHandle, CancelledExitCode);
            }

            CloseIfValid(threadHandle);
            CloseIfValid(processHandle);

            if (attributeListWasInitialized)
            {
                NativeMethods.DeleteProcThreadAttributeList(attributeList);
            }

            if (handleList != 0)
            {
                Marshal.FreeHGlobal(handleList);
            }

            if (jobList != 0)
            {
                Marshal.FreeHGlobal(jobList);
            }

            if (attributeList != 0)
            {
                Marshal.FreeHGlobal(attributeList);
            }

            CloseIfValid(childStdInput);
            CloseIfValid(childStdInputWrite);
            CloseIfValid(childStdOutput);
            CloseIfValid(childStdError);
            CloseIfValid(parentProcessHandle);
            parentInput?.Dispose();

            // Closing the final Job handle is the crash-safe cleanup path for any
            // ProxyCommand, ProxyJump, or other descendant that outlived ssh.exe.
            CloseIfValid(jobHandle);
        }
    }

    private static void StartParentLivenessMonitor(nint jobHandle, Stream input)
    {
        nint monitorJobHandle = DuplicateNonInheritableHandle(jobHandle, "Job Object");
        try
        {
            var thread = new Thread(() =>
            {
                try
                {
                    try
                    {
                        using (input)
                        {
                            while (input.ReadByte() >= 0)
                            {
                                // After the optional payload, only EOF has meaning.
                            }
                        }
                    }
                    catch (IOException)
                    {
                        // A broken control pipe is equivalent to parent death.
                    }
                }
                finally
                {
                    _ = NativeMethods.TerminateJobObject(monitorJobHandle, CancelledExitCode);
                    CloseIfValid(monitorJobHandle);
                }
            })
            {
                IsBackground = true,
                Name = "gateway-liveness",
            };

            thread.Start();
        }
        catch
        {
            input.Dispose();
            CloseIfValid(monitorJobHandle);
            throw;
        }
    }

    private static void StartParentProcessMonitor(
        nint jobHandle,
        nint parentProcessHandle)
    {
        nint monitorJobHandle = DuplicateNonInheritableHandle(
            jobHandle,
            "parent monitor Job Object");
        try
        {
            var thread = new Thread(() =>
            {
                try
                {
                    _ = NativeMethods.WaitForSingleObject(
                        parentProcessHandle,
                        Infinite);
                }
                finally
                {
                    _ = NativeMethods.TerminateJobObject(
                        monitorJobHandle,
                        CancelledExitCode);
                    CloseIfValid(parentProcessHandle);
                    CloseIfValid(monitorJobHandle);
                }
            })
            {
                IsBackground = true,
                Name = "gateway-parent-monitor",
            };

            thread.Start();
        }
        catch
        {
            CloseIfValid(monitorJobHandle);
            throw;
        }
    }

    private static void StartInputStreamForwarder(
        nint jobHandle,
        Stream input,
        nint writeHandle)
    {
        nint readerJobHandle = DuplicateNonInheritableHandle(jobHandle, "reader Job Object");
        nint writerJobHandle = 0;
        var queuedInput = new BlockingCollection<byte[]>();
        long bufferedInputBytes = 0;
        bool writerStarted = false;
        try
        {
            writerJobHandle = DuplicateNonInheritableHandle(jobHandle, "writer Job Object");
            nint ownedWriterJobHandle = writerJobHandle;
            var writerThread = new Thread(() =>
            {
                try
                {
                    using (var safeWriteHandle = new SafeFileHandle(writeHandle, ownsHandle: true))
                    using (var childInput = new FileStream(
                        safeWriteHandle,
                        FileAccess.Write,
                        bufferSize: 16 * 1024,
                        isAsync: false))
                    {
                        try
                        {
                            foreach (byte[] chunk in queuedInput.GetConsumingEnumerable())
                            {
                                childInput.Write(chunk);
                                childInput.Flush();
                                _ = Interlocked.Add(
                                    ref bufferedInputBytes,
                                    -chunk.Length);
                            }
                        }
                        catch (IOException)
                        {
                            _ = NativeMethods.TerminateJobObject(
                                ownedWriterJobHandle,
                                CancelledExitCode);
                        }
                        catch (ObjectDisposedException)
                        {
                            _ = NativeMethods.TerminateJobObject(
                                ownedWriterJobHandle,
                                CancelledExitCode);
                        }
                    }
                }
                finally
                {
                    CloseIfValid(ownedWriterJobHandle);
                }
            })
            {
                IsBackground = true,
                Name = "gateway-stdin-writer",
            };

            var readerThread = new Thread(() =>
            {
                try
                {
                    using (input)
                    {
                        byte[] buffer = new byte[16 * 1024];
                        while (true)
                        {
                            int read = input.Read(buffer, 0, buffer.Length);
                            if (read == 0)
                            {
                                break;
                            }

                            long pendingBytes = Interlocked.Add(
                                ref bufferedInputBytes,
                                read);
                            if (pendingBytes > MaxBufferedStreamInputBytes)
                            {
                                _ = Interlocked.Add(ref bufferedInputBytes, -read);
                                break;
                            }
                            queuedInput.Add(buffer.AsSpan(0, read).ToArray());
                        }
                    }
                }
                catch (IOException)
                {
                    // A broken parent pipe is equivalent to parent death.
                }
                catch (ObjectDisposedException)
                {
                    // Treat a concurrently closed control pipe as parent death.
                }
                finally
                {
                    queuedInput.CompleteAdding();
                    _ = NativeMethods.TerminateJobObject(
                        readerJobHandle,
                        CancelledExitCode);
                    CloseIfValid(readerJobHandle);
                }
            })
            {
                IsBackground = true,
                Name = "gateway-stdin-reader",
            };

            writerThread.Start();
            writerStarted = true;
            writerJobHandle = 0;
            readerThread.Start();
        }
        catch
        {
            input.Dispose();
            queuedInput.CompleteAdding();
            if (!writerStarted)
            {
                CloseIfValid(writeHandle);
            }
            _ = NativeMethods.TerminateJobObject(readerJobHandle, CancelledExitCode);
            CloseIfValid(readerJobHandle);
            _ = NativeMethods.TerminateJobObject(writerJobHandle, CancelledExitCode);
            CloseIfValid(writerJobHandle);
            throw;
        }
    }

    private static void ForwardInputPayload(Stream parentInput, nint writeHandle)
    {
        using var safeWriteHandle = new SafeFileHandle(writeHandle, ownsHandle: true);
        using var childInput = new FileStream(
            safeWriteHandle,
            FileAccess.Write,
            bufferSize: 16 * 1024,
            isAsync: false);

        Span<byte> header = stackalloc byte[4];
        parentInput.ReadExactly(header);
        uint payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (payloadLength > MaxChildStandardInputBytes)
        {
            throw new InvalidDataException("the child standard input payload exceeds the limit");
        }

        byte[] buffer = new byte[16 * 1024];
        uint remaining = payloadLength;
        while (remaining > 0)
        {
            int requested = (int)Math.Min((uint)buffer.Length, remaining);
            int read = parentInput.Read(buffer, 0, requested);
            if (read == 0)
            {
                throw new EndOfStreamException("the child standard input payload ended early");
            }
            childInput.Write(buffer, 0, read);
            remaining -= (uint)read;
        }
        childInput.Flush();
    }

    private static void CreateInheritableInputPipe(
        out nint readHandle,
        out nint writeHandle)
    {
        var security = new SecurityAttributes
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            InheritHandle = true,
        };

        if (!NativeMethods.CreatePipe(
                out readHandle,
                out writeHandle,
                ref security,
                0))
        {
            throw LastWin32("CreatePipe(stdin)");
        }

        if (!NativeMethods.SetHandleInformation(
                writeHandle,
                HandleFlagInherit,
                0))
        {
            int error = Marshal.GetLastWin32Error();
            CloseIfValid(readHandle);
            CloseIfValid(writeHandle);
            readHandle = 0;
            writeHandle = 0;
            throw new Win32Exception(
                error,
                $"SetHandleInformation(stdin) failed: {new Win32Exception(error).Message}");
        }
    }

    private static nint CreateInheritableNullInput()
    {
        var security = new SecurityAttributes
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            InheritHandle = true,
        };

        nint handle = NativeMethods.CreateFileW(
            "NUL",
            GenericRead,
            FileShareRead | FileShareWrite,
            ref security,
            OpenExisting,
            FileAttributeNormal,
            0);
        ThrowIfInvalid(handle, "CreateFileW(NUL)");
        return handle;
    }

    private static nint DuplicateInheritableStandardHandle(int standardHandle, string name)
    {
        nint source = NativeMethods.GetStdHandle(standardHandle);
        ThrowIfInvalid(source, $"GetStdHandle({name})");

        nint currentProcess = NativeMethods.GetCurrentProcess();
        if (!NativeMethods.DuplicateHandle(
                currentProcess,
                source,
                currentProcess,
                out nint duplicate,
                0,
                true,
                DuplicateSameAccess))
        {
            throw LastWin32($"DuplicateHandle({name})");
        }

        return duplicate;
    }

    private static nint DuplicateNonInheritableHandle(nint source, string name)
    {
        nint currentProcess = NativeMethods.GetCurrentProcess();
        if (!NativeMethods.DuplicateHandle(
                currentProcess,
                source,
                currentProcess,
                out nint duplicate,
                0,
                false,
                DuplicateSameAccess))
        {
            throw LastWin32($"DuplicateHandle({name})");
        }

        return duplicate;
    }

    internal static string BuildCommandLine(string executable, ReadOnlySpan<string> arguments)
    {
        var commandLine = new StringBuilder(QuoteArgument(executable));
        foreach (string argument in arguments)
        {
            if (argument.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("child arguments must not contain NUL characters");
            }

            commandLine.Append(' ');
            commandLine.Append(QuoteArgument(argument));
        }

        // CreateProcessW includes the terminating NUL in its 32,767-character limit.
        if (commandLine.Length >= 32_767)
        {
            throw new ArgumentException("the child command line exceeds the Windows limit");
        }

        return commandLine.ToString();
    }

    internal static string QuoteArgument(string argument)
    {
        if (argument.Length == 0)
        {
            return "\"\"";
        }

        bool needsQuotes = argument.Any(character =>
            character is ' ' or '\t' or '\n' or '\v' or '\"');
        if (!needsQuotes)
        {
            return argument;
        }

        var quoted = new StringBuilder(argument.Length + 2);
        quoted.Append('\"');
        int backslashCount = 0;

        foreach (char character in argument)
        {
            if (character == '\\')
            {
                backslashCount++;
                continue;
            }

            if (character == '\"')
            {
                quoted.Append('\\', (backslashCount * 2) + 1);
                quoted.Append('\"');
                backslashCount = 0;
                continue;
            }

            quoted.Append('\\', backslashCount);
            backslashCount = 0;
            quoted.Append(character);
        }

        quoted.Append('\\', backslashCount * 2);
        quoted.Append('\"');
        return quoted.ToString();
    }

    private static bool IsProcessActive(nint processHandle) =>
        NativeMethods.GetExitCodeProcess(processHandle, out uint exitCode) && exitCode == StillActive;

    private static void ThrowIfInvalid(nint handle, string operation)
    {
        if (handle == 0 || handle == -1)
        {
            throw LastWin32(operation);
        }
    }

    private static Win32Exception LastWin32(string operation)
    {
        int error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, $"{operation} failed: {new Win32Exception(error).Message}");
    }

    private static void CloseIfValid(nint handle)
    {
        if (handle != 0 && handle != -1)
        {
            _ = NativeMethods.CloseHandle(handle);
        }
    }
}

internal enum JobObjectInformationClass
{
    ExtendedLimitInformation = 9,
}

[StructLayout(LayoutKind.Sequential)]
internal struct SecurityAttributes
{
    public int Length;
    public nint SecurityDescriptor;

    [MarshalAs(UnmanagedType.Bool)]
    public bool InheritHandle;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct StartupInfo
{
    public int Cb;
    public string? Reserved;
    public string? Desktop;
    public string? Title;
    public uint X;
    public uint Y;
    public uint XSize;
    public uint YSize;
    public uint XCountChars;
    public uint YCountChars;
    public uint FillAttribute;
    public uint Flags;
    public ushort ShowWindow;
    public ushort Reserved2Bytes;
    public nint Reserved2;
    public nint StandardInput;
    public nint StandardOutput;
    public nint StandardError;
}

[StructLayout(LayoutKind.Sequential)]
internal struct StartupInfoEx
{
    public StartupInfo StartupInfo;
    public nint AttributeList;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ProcessInformation
{
    public nint Process;
    public nint Thread;
    public uint ProcessId;
    public uint ThreadId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct JobObjectBasicLimitInformation
{
    public long PerProcessUserTimeLimit;
    public long PerJobUserTimeLimit;
    public uint LimitFlags;
    public nuint MinimumWorkingSetSize;
    public nuint MaximumWorkingSetSize;
    public uint ActiveProcessLimit;
    public nuint Affinity;
    public uint PriorityClass;
    public uint SchedulingClass;
}

[StructLayout(LayoutKind.Sequential)]
internal struct IoCounters
{
    public ulong ReadOperationCount;
    public ulong WriteOperationCount;
    public ulong OtherOperationCount;
    public ulong ReadTransferCount;
    public ulong WriteTransferCount;
    public ulong OtherTransferCount;
}

[StructLayout(LayoutKind.Sequential)]
internal struct JobObjectExtendedLimitInformation
{
    public JobObjectBasicLimitInformation BasicLimitInformation;
    public IoCounters IoInfo;
    public nuint ProcessMemoryLimit;
    public nuint JobMemoryLimit;
    public nuint PeakProcessMemoryUsed;
    public nuint PeakJobMemoryUsed;
}

internal static partial class NativeMethods
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreatePipe(
        out nint readPipe,
        out nint writePipe,
        ref SecurityAttributes pipeAttributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetHandleInformation(
        nint handle,
        uint mask,
        uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern nint CreateJobObjectW(nint jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern nint OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(
        nint job,
        JobObjectInformationClass informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        nint processAttributes,
        nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        nint environment,
        string? currentDirectory,
        ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint ResumeThread(nint thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(nint handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(nint process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(nint process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateJobObject(nint job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(nint handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern nint GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll")]
    internal static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DuplicateHandle(
        nint sourceProcess,
        nint sourceHandle,
        nint targetProcess,
        out nint targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern nint CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        ref SecurityAttributes securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        nint templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool InitializeProcThreadAttributeList(
        nint attributeList,
        int attributeCount,
        uint flags,
        ref nuint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UpdateProcThreadAttribute(
        nint attributeList,
        uint flags,
        nuint attribute,
        nint value,
        nuint size,
        nint previousValue,
        nint returnSize);

    [DllImport("kernel32.dll")]
    internal static extern void DeleteProcThreadAttributeList(nint attributeList);
}

using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SarifRegress.Sarif.Repository;

/// <summary>
/// Opens repository files relative to an anchored directory handle without
/// following symbolic links or Windows reparse points.
/// </summary>
internal static class RepositoryFileHandleOpener
{
    private const int StreamBufferBytes = 16 * 1024;

    /// <summary>
    /// Opens a regular repository file through the platform's handle-relative API.
    /// </summary>
    /// <param name="repositoryRoot">The lexically canonical approved root.</param>
    /// <param name="repositoryRelativePath">
    /// A validated path relative to <paramref name="repositoryRoot"/>.
    /// </param>
    /// <returns>A fixed file handle or a classified failure.</returns>
    public static RepositoryFileOpenResult Open(
        string repositoryRoot,
        string repositoryRelativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRelativePath);

        try
        {
            if (OperatingSystem.IsLinux())
            {
                return LinuxRepositoryFileOpener.Open(
                    repositoryRoot,
                    repositoryRelativePath);
            }

            if (OperatingSystem.IsWindows())
            {
                return WindowsRepositoryFileOpener.Open(
                    repositoryRoot,
                    repositoryRelativePath);
            }
        }
        catch (Exception exception)
            when (exception is DllNotFoundException
                or EntryPointNotFoundException
                or MarshalDirectiveException
                or PlatformNotSupportedException)
        {
            return RepositoryFileOpenResult.Failed(
                RepositoryFileOpenFailure.SafetyUnavailable);
        }

        return RepositoryFileOpenResult.Failed(
            RepositoryFileOpenFailure.SafetyUnavailable);
    }

    /// <summary>
    /// Wraps an owned native file handle in the stream used by repository reads.
    /// </summary>
    internal static RepositoryFileOpenResult CreateSuccess(
        SafeFileHandle fileHandle)
    {
        try
        {
            var stream = new FileStream(
                fileHandle,
                FileAccess.Read,
                StreamBufferBytes,
                isAsync: false);
            return RepositoryFileOpenResult.Succeeded(stream);
        }
        catch (IOException)
        {
            fileHandle.Dispose();
            return RepositoryFileOpenResult.Failed(
                RepositoryFileOpenFailure.IoError);
        }
        catch (UnauthorizedAccessException)
        {
            fileHandle.Dispose();
            return RepositoryFileOpenResult.Failed(
                RepositoryFileOpenFailure.AccessDenied);
        }
        catch (NotSupportedException)
        {
            fileHandle.Dispose();
            return RepositoryFileOpenResult.Failed(
                RepositoryFileOpenFailure.UnsupportedFileType);
        }
        catch (ArgumentException)
        {
            fileHandle.Dispose();
            return RepositoryFileOpenResult.Failed(
                RepositoryFileOpenFailure.IoError);
        }
    }
}

/// <summary>
/// Classifies a native repository-file open failure.
/// </summary>
internal enum RepositoryFileOpenFailure
{
    None,
    NotFound,
    UnsafePath,
    UnsupportedFileType,
    AccessDenied,
    IoError,
    SafetyUnavailable,
}

/// <summary>
/// Carries either the fixed stream selected by a safe native open or its failure.
/// </summary>
internal readonly record struct RepositoryFileOpenResult(
    FileStream? Stream,
    RepositoryFileOpenFailure Failure)
{
    /// <summary>
    /// Creates a successful open result.
    /// </summary>
    public static RepositoryFileOpenResult Succeeded(FileStream stream) =>
        new(stream, RepositoryFileOpenFailure.None);

    /// <summary>
    /// Creates a failed open result.
    /// </summary>
    public static RepositoryFileOpenResult Failed(
        RepositoryFileOpenFailure failure)
    {
        if (failure is RepositoryFileOpenFailure.None)
        {
            throw new ArgumentOutOfRangeException(
                nameof(failure),
                failure,
                "A failed repository open requires a failure classification.");
        }

        return new RepositoryFileOpenResult(null, failure);
    }
}

/// <summary>
/// Linux implementation using an anchored directory descriptor and
/// <c>openat2</c> resolution constraints.
/// </summary>
internal static class LinuxRepositoryFileOpener
{
    internal const int ErrorAccessDenied = 13;
    internal const int ErrorAgain = 11;
    internal const int ErrorArgumentListTooLong = 7;
    internal const int ErrorCrossDevice = 18;
    internal const int ErrorInvalidArgument = 22;
    internal const int ErrorIsSymbolicLink = 40;
    internal const int ErrorNoEntry = 2;
    internal const int ErrorNoSuchDeviceOrAddress = 6;
    internal const int ErrorNoSystemCall = 38;
    internal const int ErrorNotDirectory = 20;
    internal const int ErrorOperationNotPermitted = 1;

    private const long OpenAt2SystemCall = 437;
    private const long StatxArm64SystemCall = 291;
    private const long StatxX64SystemCall = 332;
    private const int OpenReadOnly = 0;
    private const int OpenCloseOnExec = 0x0008_0000;
    private const int OpenDirectory = 0x0001_0000;
    private const int OpenNoFollow = 0x0002_0000;
    private const int OpenNonBlocking = 0x0000_0800;
    private const ulong ResolveNoCrossDevice = 0x01;
    private const ulong ResolveNoMagicLinks = 0x02;
    private const ulong ResolveNoSymbolicLinks = 0x04;
    private const ulong ResolveBeneath = 0x08;
    private const int StatxEmptyPath = 0x1000;
    private const uint StatxType = 0x0000_0001;
    private const int StatxModeOffset = 28;
    private const int StatxBufferBytes = 256;
    private const int FileTypeMask = 0xF000;
    private const int RegularFileType = 0x8000;

    /// <summary>
    /// Opens a repository file without a pathname-check/open race.
    /// </summary>
    public static RepositoryFileOpenResult Open(
        string repositoryRoot,
        string repositoryRelativePath)
    {
        if (RuntimeInformation.ProcessArchitecture is not
            (Architecture.X64 or Architecture.Arm64))
        {
            return RepositoryFileOpenResult.Failed(
                RepositoryFileOpenFailure.SafetyUnavailable);
        }

        var rootDescriptor = NativeOpen(
            repositoryRoot,
            OpenReadOnly |
            OpenCloseOnExec |
            OpenDirectory |
            OpenNoFollow);
        if (rootDescriptor < 0)
        {
            return RepositoryFileOpenResult.Failed(
                ClassifyError(Marshal.GetLastPInvokeError()));
        }

        using var rootHandle = new SafeFileHandle(
            (nint)rootDescriptor,
            ownsHandle: true);
        var openHow = new OpenHow
        {
            Flags =
                OpenReadOnly |
                OpenCloseOnExec |
                OpenNoFollow |
                OpenNonBlocking,
            Resolve =
                ResolveNoCrossDevice |
                ResolveNoMagicLinks |
                ResolveNoSymbolicLinks |
                ResolveBeneath,
        };
        var fileDescriptor = NativeOpenAt2(
            OpenAt2SystemCall,
            rootDescriptor,
            repositoryRelativePath,
            ref openHow,
            (nuint)Marshal.SizeOf<OpenHow>());
        if (fileDescriptor < 0)
        {
            return RepositoryFileOpenResult.Failed(
                ClassifyError(Marshal.GetLastPInvokeError()));
        }

        var fileHandle = new SafeFileHandle(
            (nint)fileDescriptor,
            ownsHandle: true);
        try
        {
            var fileTypeFailure = ValidateRegularFile(
                fileDescriptor,
                RuntimeInformation.ProcessArchitecture);
            if (fileTypeFailure is not RepositoryFileOpenFailure.None)
            {
                fileHandle.Dispose();
                return RepositoryFileOpenResult.Failed(fileTypeFailure);
            }

            return RepositoryFileHandleOpener.CreateSuccess(fileHandle);
        }
        catch
        {
            fileHandle.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Maps Linux errors without weakening an unavailable containment primitive.
    /// </summary>
    internal static RepositoryFileOpenFailure ClassifyError(int error) =>
        error switch
        {
            ErrorNoEntry => RepositoryFileOpenFailure.NotFound,
            ErrorNoSuchDeviceOrAddress =>
                RepositoryFileOpenFailure.UnsupportedFileType,
            ErrorIsSymbolicLink or
                ErrorCrossDevice or
                ErrorNotDirectory =>
                RepositoryFileOpenFailure.UnsafePath,
            ErrorAccessDenied or
                ErrorOperationNotPermitted =>
                RepositoryFileOpenFailure.AccessDenied,
            ErrorAgain or
                ErrorArgumentListTooLong or
                ErrorInvalidArgument or
                ErrorNoSystemCall =>
                RepositoryFileOpenFailure.SafetyUnavailable,
            _ => RepositoryFileOpenFailure.IoError,
        };

    private static RepositoryFileOpenFailure ValidateRegularFile(
        long fileDescriptor,
        Architecture architecture)
    {
        var statxSystemCall = architecture switch
        {
            Architecture.X64 => StatxX64SystemCall,
            Architecture.Arm64 => StatxArm64SystemCall,
            _ => 0,
        };
        if (statxSystemCall == 0)
        {
            return RepositoryFileOpenFailure.SafetyUnavailable;
        }

        var statxBuffer = Marshal.AllocHGlobal(StatxBufferBytes);
        try
        {
            var result = NativeStatx(
                statxSystemCall,
                (int)fileDescriptor,
                string.Empty,
                StatxEmptyPath,
                StatxType,
                statxBuffer);
            if (result < 0)
            {
                return ClassifyError(Marshal.GetLastPInvokeError());
            }

            var returnedMask = unchecked(
                (uint)Marshal.ReadInt32(statxBuffer));
            if ((returnedMask & StatxType) == 0)
            {
                return RepositoryFileOpenFailure.SafetyUnavailable;
            }

            var mode = (ushort)Marshal.ReadInt16(
                statxBuffer,
                StatxModeOffset);
            return (mode & FileTypeMask) == RegularFileType
                ? RepositoryFileOpenFailure.None
                : RepositoryFileOpenFailure.UnsupportedFileType;
        }
        finally
        {
            Marshal.FreeHGlobal(statxBuffer);
        }
    }

    [DllImport(
        "libc",
        EntryPoint = "open",
        SetLastError = true,
        CharSet = CharSet.Ansi)]
    private static extern int NativeOpen(string path, int flags);

    [DllImport(
        "libc",
        EntryPoint = "syscall",
        SetLastError = true,
        CharSet = CharSet.Ansi)]
    private static extern long NativeOpenAt2(
        long systemCall,
        int directoryDescriptor,
        string path,
        ref OpenHow openHow,
        nuint size);

    [DllImport(
        "libc",
        EntryPoint = "syscall",
        SetLastError = true,
        CharSet = CharSet.Ansi)]
    private static extern long NativeStatx(
        long systemCall,
        int fileDescriptor,
        string path,
        int flags,
        uint mask,
        nint statxBuffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct OpenHow
    {
        public ulong Flags;

        public ulong Mode;

        public ulong Resolve;
    }
}

/// <summary>
/// Windows implementation using fixed directory handles and segment-by-segment
/// relative <c>NtCreateFile</c> opens with <c>FILE_OPEN_REPARSE_POINT</c>.
/// </summary>
internal static class WindowsRepositoryFileOpener
{
    internal const int ErrorAccessDenied = 5;
    internal const int ErrorCallNotImplemented = 120;
    internal const int ErrorCannotAccessFile = 1920;
    internal const int ErrorFileNotFound = 2;
    internal const int ErrorInvalidParameter = 87;
    internal const int ErrorNotADirectory = 267;
    internal const int ErrorNotSupported = 50;
    internal const int ErrorPathNotFound = 3;
    internal const int ErrorReparseTagInvalid = 4393;
    internal const int ErrorReparseTagMismatch = 4394;

    internal const int StatusReparsePointEncountered =
        unchecked((int)0xC000050B);
    internal const int StatusStoppedOnSymbolicLink =
        unchecked((int)0x8000002D);
    internal const int StatusFileIsDirectory =
        unchecked((int)0xC00000BA);
    internal const int StatusObjectTypeMismatch =
        unchecked((int)0xC0000024);

    private const uint FileAttributeDirectory = 0x0000_0010;
    private const uint FileAttributeReparsePoint = 0x0000_0400;
    private const uint FileTypeDisk = 0x0000_0001;
    private const uint FileFlagBackupSemantics = 0x0200_0000;
    private const uint FileFlagOpenReparsePoint = 0x0020_0000;
    private const uint FileGenericRead = 0x0012_0089;
    private const uint FileOpenReparsePoint = 0x0020_0000;
    private const uint FileTraverse = 0x0000_0020;
    private const uint FileNonDirectoryFile = 0x0000_0040;
    private const uint FileOpen = 0x0000_0001;
    private const uint FileOpenExisting = 3;
    private const uint FileReadAttributes = 0x0000_0080;
    private const uint FileSequentialOnly = 0x0000_0004;
    private const uint FileShareDelete = 0x0000_0004;
    private const uint FileShareRead = 0x0000_0001;
    private const uint FileShareWrite = 0x0000_0002;
    private const uint FileSynchronousIoNonAlert = 0x0000_0020;
    private const uint ObjectCaseInsensitive = 0x0000_0040;
    private const uint Synchronize = 0x0010_0000;
    private const int FileAttributeTagInfoClass = 9;

    /// <summary>
    /// Opens a repository file without following any relative-path reparse point.
    /// </summary>
    public static RepositoryFileOpenResult Open(
        string repositoryRoot,
        string repositoryRelativePath)
    {
        using var rootHandle = CreateFile(
            repositoryRoot,
            FileTraverse | FileReadAttributes | Synchronize,
            FileShareRead | FileShareWrite | FileShareDelete,
            nint.Zero,
            FileOpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            nint.Zero);
        if (rootHandle.IsInvalid)
        {
            return RepositoryFileOpenResult.Failed(
                ClassifyError(Marshal.GetLastPInvokeError()));
        }

        var rootFailure = ValidateDirectory(rootHandle);
        if (rootFailure is not RepositoryFileOpenFailure.None)
        {
            return RepositoryFileOpenResult.Failed(
                rootFailure);
        }

        return OpenRelative(rootHandle, repositoryRelativePath);
    }

    /// <summary>
    /// Maps a Windows error while preserving reparse and capability failures.
    /// </summary>
    internal static RepositoryFileOpenFailure ClassifyError(int error) =>
        error switch
        {
            ErrorFileNotFound or
                ErrorPathNotFound =>
                RepositoryFileOpenFailure.NotFound,
            ErrorCannotAccessFile or
                ErrorNotADirectory or
                ErrorReparseTagInvalid or
                ErrorReparseTagMismatch =>
                RepositoryFileOpenFailure.UnsafePath,
            ErrorAccessDenied =>
                RepositoryFileOpenFailure.AccessDenied,
            ErrorCallNotImplemented or
                ErrorInvalidParameter or
                ErrorNotSupported =>
                RepositoryFileOpenFailure.SafetyUnavailable,
            _ => RepositoryFileOpenFailure.IoError,
        };

    /// <summary>
    /// Maps a native status, detecting reparse refusal before Win32 conversion.
    /// </summary>
    internal static RepositoryFileOpenFailure ClassifyStatus(
        int status,
        int convertedError)
    {
        if (status is StatusReparsePointEncountered or
            StatusStoppedOnSymbolicLink)
        {
            return RepositoryFileOpenFailure.UnsafePath;
        }

        if (status is StatusFileIsDirectory or StatusObjectTypeMismatch)
        {
            return RepositoryFileOpenFailure.UnsupportedFileType;
        }

        return ClassifyError(convertedError);
    }

    private static RepositoryFileOpenResult OpenRelative(
        SafeFileHandle rootHandle,
        string repositoryRelativePath)
    {
        var segments = repositoryRelativePath.Split(
            new[] { '\\', '/' },
            StringSplitOptions.None);
        if (segments.Length == 0
            || segments.Any(segment =>
                segment.Length == 0
                || segment == "."
                || segment == ".."))
        {
            return RepositoryFileOpenResult.Failed(
                RepositoryFileOpenFailure.UnsafePath);
        }

        SafeFileHandle? retainedDirectoryHandle = null;
        try
        {
            var parentHandle = rootHandle;
            for (var index = 0; index < segments.Length - 1; index++)
            {
                var directoryOpenFailure = OpenRelativeHandle(
                    parentHandle,
                    segments[index],
                    FileTraverse | FileReadAttributes | Synchronize,
                    FileShareRead | FileShareWrite | FileShareDelete,
                    FileOpenReparsePoint |
                        FileSynchronousIoNonAlert,
                    out var directoryHandle);
                if (directoryOpenFailure is not
                    RepositoryFileOpenFailure.None)
                {
                    return RepositoryFileOpenResult.Failed(
                        directoryOpenFailure);
                }

                var retainedHandle = directoryHandle
                    ?? throw new InvalidOperationException(
                        "A successful relative directory open must return a handle.");
                RepositoryFileOpenFailure directoryValidationFailure;
                try
                {
                    directoryValidationFailure =
                        ValidateDirectory(retainedHandle);
                }
                catch
                {
                    retainedHandle.Dispose();
                    throw;
                }

                if (directoryValidationFailure is not
                    RepositoryFileOpenFailure.None)
                {
                    retainedHandle.Dispose();
                    return RepositoryFileOpenResult.Failed(
                        directoryValidationFailure);
                }

                retainedDirectoryHandle?.Dispose();
                retainedDirectoryHandle = retainedHandle;
                parentHandle = retainedHandle;
            }

            var fileOpenFailure = OpenRelativeHandle(
                parentHandle,
                segments[^1],
                FileGenericRead,
                FileShareRead | FileShareDelete,
                FileNonDirectoryFile |
                    FileOpenReparsePoint |
                    FileSequentialOnly |
                    FileSynchronousIoNonAlert,
                out var fileHandle);
            if (fileOpenFailure is not
                RepositoryFileOpenFailure.None)
            {
                return RepositoryFileOpenResult.Failed(
                    fileOpenFailure);
            }

            var retainedFileHandle = fileHandle
                ?? throw new InvalidOperationException(
                    "A successful relative file open must return a handle.");
            RepositoryFileOpenFailure fileTypeFailure;
            try
            {
                fileTypeFailure = ValidateRegularFile(
                    retainedFileHandle);
            }
            catch
            {
                retainedFileHandle.Dispose();
                throw;
            }

            if (fileTypeFailure is not RepositoryFileOpenFailure.None)
            {
                retainedFileHandle.Dispose();
                return RepositoryFileOpenResult.Failed(
                    fileTypeFailure);
            }

            return RepositoryFileHandleOpener.CreateSuccess(
                retainedFileHandle);
        }
        finally
        {
            retainedDirectoryHandle?.Dispose();
        }
    }

    private static RepositoryFileOpenFailure OpenRelativeHandle(
        SafeFileHandle parentHandle,
        string segment,
        uint desiredAccess,
        uint shareAccess,
        uint createOptions,
        out SafeFileHandle? openedHandle)
    {
        openedHandle = null;
        var segmentByteLength =
            (long)segment.Length * sizeof(char);
        if (segmentByteLength > ushort.MaxValue - sizeof(char))
        {
            return RepositoryFileOpenFailure.IoError;
        }

        var segmentBuffer = Marshal.StringToHGlobalUni(segment);
        var unicodeStringBuffer = Marshal.AllocHGlobal(
            Marshal.SizeOf<UnicodeString>());
        try
        {
            var unicodeString = new UnicodeString
            {
                Length = (ushort)segmentByteLength,
                MaximumLength =
                    (ushort)(segmentByteLength + sizeof(char)),
                Buffer = segmentBuffer,
            };
            Marshal.StructureToPtr(
                unicodeString,
                unicodeStringBuffer,
                fDeleteOld: false);
            var objectAttributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = parentHandle.DangerousGetHandle(),
                ObjectName = unicodeStringBuffer,
                Attributes = ObjectCaseInsensitive,
            };
            var status = NtCreateFile(
                out var nativeHandle,
                desiredAccess,
                ref objectAttributes,
                out _,
                nint.Zero,
                fileAttributes: 0,
                shareAccess,
                FileOpen,
                createOptions,
                nint.Zero,
                eaLength: 0);
            GC.KeepAlive(parentHandle);
            if (status < 0)
            {
                return ClassifyStatus(
                    status,
                    unchecked((int)RtlNtStatusToDosError(status)));
            }

            var safeHandle = new SafeFileHandle(
                nativeHandle,
                ownsHandle: true);
            if (safeHandle.IsInvalid)
            {
                safeHandle.Dispose();
                return RepositoryFileOpenFailure.IoError;
            }

            openedHandle = safeHandle;
            return RepositoryFileOpenFailure.None;
        }
        finally
        {
            Marshal.FreeHGlobal(unicodeStringBuffer);
            Marshal.FreeHGlobal(segmentBuffer);
        }
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        SetLastError = true,
        CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        nint securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        nint templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle fileHandle,
        int fileInformationClass,
        out FileAttributeTagInformation fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle fileHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(
        out nint fileHandle,
        uint desiredAccess,
        ref ObjectAttributes objectAttributes,
        out IoStatusBlock ioStatusBlock,
        nint allocationSize,
        uint fileAttributes,
        uint shareAccess,
        uint createDisposition,
        uint createOptions,
        nint eaBuffer,
        uint eaLength);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);

    private static RepositoryFileOpenFailure ValidateRegularFile(
        SafeFileHandle fileHandle)
    {
        var attributeFailure = GetValidatedAttributes(
            fileHandle,
            out var fileAttributes);
        if (attributeFailure is not RepositoryFileOpenFailure.None)
        {
            return attributeFailure;
        }

        return (fileAttributes & FileAttributeDirectory) == 0
            ? RepositoryFileOpenFailure.None
            : RepositoryFileOpenFailure.UnsupportedFileType;
    }

    private static RepositoryFileOpenFailure ValidateDirectory(
        SafeFileHandle directoryHandle)
    {
        var attributeFailure = GetValidatedAttributes(
            directoryHandle,
            out var fileAttributes);
        if (attributeFailure is not RepositoryFileOpenFailure.None)
        {
            return attributeFailure;
        }

        return (fileAttributes & FileAttributeDirectory) != 0
            ? RepositoryFileOpenFailure.None
            : RepositoryFileOpenFailure.UnsafePath;
    }

    private static RepositoryFileOpenFailure GetValidatedAttributes(
        SafeFileHandle fileHandle,
        out uint fileAttributes)
    {
        fileAttributes = 0;
        if (GetFileType(fileHandle) != FileTypeDisk)
        {
            return RepositoryFileOpenFailure.UnsupportedFileType;
        }

        if (!GetFileInformationByHandleEx(
                fileHandle,
                FileAttributeTagInfoClass,
                out var fileInformation,
                (uint)Marshal.SizeOf<FileAttributeTagInformation>()))
        {
            return ClassifyError(Marshal.GetLastPInvokeError());
        }

        if ((fileInformation.FileAttributes & FileAttributeReparsePoint) != 0)
        {
            return RepositoryFileOpenFailure.UnsafePath;
        }

        fileAttributes = fileInformation.FileAttributes;
        return RepositoryFileOpenFailure.None;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInformation
    {
        public uint FileAttributes;

        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public nint Status;

        public nuint Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;

        public nint RootDirectory;

        public nint ObjectName;

        public uint Attributes;

        public nint SecurityDescriptor;

        public nint SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;

        public ushort MaximumLength;

        public nint Buffer;
    }
}

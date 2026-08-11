using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Security;
using SarifRegress.Sarif.Repository;

namespace SarifRegress.UnitTests;

public sealed class RepositoryContextTests
{
    [Fact]
    public async Task Read_returns_a_bounded_normalized_snippet_and_hash()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            var sourceDirectory = Directory.CreateDirectory(
                Path.Combine(root.FullName, "src"));
            await File.WriteAllTextAsync(
                Path.Combine(sourceDirectory.FullName, "a.cs"),
                "line one\r\nline two\r\nline three",
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                TestContext.Current.CancellationToken);
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "src/a.cs",
                new Region(2, 1, 2, 4),
                lineRadius: 1,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.True(result.Exists);
            Assert.Equal(
                "line one\nline two\nline three",
                result.Snippet);
            Assert.NotNull(result.Evidence?.SnippetHash);
            Assert.Equal(1, result.Evidence?.StartLine);
            Assert.Equal(3, result.Evidence?.EndLine);
            Assert.Empty(result.Diagnostics);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Parent_traversal_is_rejected_before_file_access()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "../outside.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.False(result.Exists);
            var diagnostic = Assert.Single(result.Diagnostics);
            Assert.Equal("SECURITY0001", diagnostic.Code);
            Assert.Equal(DiagnosticStage.Security, diagnostic.Stage);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Source_file_byte_limit_is_enforced()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "large.txt"),
                "12345",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            var limits = ResourceLimits.Default with
            {
                MaximumRepositoryFileBytes = 4,
            };
            var context = new FileSystemRepositoryContext(
                root.FullName,
                limits);

            var result = await context.ReadAsync(
                "large.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.True(result.Exists);
            Assert.Null(result.Evidence);
            Assert.Contains(
                result.Diagnostics,
                item =>
                    item.Code == "SECURITY0003" &&
                    item.Severity == DiagnosticSeverity.Error);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Invalid_utf8_is_reported_without_replacement_characters()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            await File.WriteAllBytesAsync(
                Path.Combine(root.FullName, "invalid.txt"),
                [0xC3, 0x28],
                TestContext.Current.CancellationToken);
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "invalid.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Null(result.Snippet);
            Assert.Contains(
                result.Diagnostics,
                item => item.Code == "IO0004");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Two_reads_of_the_same_source_produce_identical_evidence()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "stable.txt"),
                "alpha\nbeta\ngamma",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            var context = new FileSystemRepositoryContext(root.FullName);
            var region = new Region(2, null, null, null);

            var first = await context.ReadAsync(
                "stable.txt",
                region,
                lineRadius: 1,
                cancellationToken: TestContext.Current.CancellationToken);
            var second = await context.ReadAsync(
                "stable.txt",
                region,
                lineRadius: 1,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(first.Snippet, second.Snippet);
            Assert.Equal(
                first.Evidence?.SnippetHash,
                second.Evidence?.SnippetHash);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Maximum_region_coordinates_are_clamped_without_overflow()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-repo-");
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "small.txt"),
                "only line",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "small.txt",
                new Region(1, 1, int.MaxValue, 1),
                lineRadius: ResourceLimits.Default.MaximumSnippetRadius,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal("only line", result.Snippet);
            Assert.Equal(1, result.Evidence?.EndLine);
            Assert.DoesNotContain(
                result.Diagnostics,
                item => item.Severity == DiagnosticSeverity.Error);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Symbolic_links_at_every_repository_level_are_rejected()
    {
        var parent = Directory.CreateTempSubdirectory("sarif-regress-links-");
        try
        {
            var root = Directory.CreateDirectory(
                Path.Combine(parent.FullName, "root"));
            var outside = Directory.CreateDirectory(
                Path.Combine(parent.FullName, "outside"));
            var outsideFile = Path.Combine(outside.FullName, "secret.txt");
            var regularFile = Path.Combine(root.FullName, "regular.txt");
            await File.WriteAllTextAsync(
                outsideFile,
                "secret",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(
                regularFile,
                "regular",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);

            var fileLink = Path.Combine(root.FullName, "file-link.txt");
            var directoryLink = Path.Combine(root.FullName, "directory-link");
            var rootLink = Path.Combine(parent.FullName, "root-link");
            try
            {
                File.CreateSymbolicLink(fileLink, outsideFile);
                Directory.CreateSymbolicLink(directoryLink, outside.FullName);
                Directory.CreateSymbolicLink(rootLink, root.FullName);
            }
            catch (Exception exception)
                when (exception is IOException
                    or UnauthorizedAccessException
                    or PlatformNotSupportedException)
            {
                return;
            }

            var context = new FileSystemRepositoryContext(root.FullName);
            var fileResult = await context.ReadAsync(
                "file-link.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);
            var directoryResult = await context.ReadAsync(
                "directory-link/secret.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);
            var rootResult = await new FileSystemRepositoryContext(
                $"{rootLink}{Path.DirectorySeparatorChar}")
                .ReadAsync(
                    "regular.txt",
                    new Region(1, null, null, null),
                    lineRadius: 0,
                    cancellationToken: TestContext.Current.CancellationToken);

            Assert.Contains(
                fileResult.Diagnostics,
                item => item.Code == "SECURITY0002");
            Assert.Contains(
                directoryResult.Diagnostics,
                item => item.Code == "SECURITY0002");
            Assert.Contains(
                rootResult.Diagnostics,
                item => item.Code == "SECURITY0002");
            Assert.Null(fileResult.Snippet);
            Assert.Null(directoryResult.Snippet);
            Assert.Null(rootResult.Snippet);
        }
        finally
        {
            parent.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Symbolic_link_in_repository_root_ancestry_is_rejected()
    {
        var parent = Directory.CreateTempSubdirectory(
            "sarif-regress-root-ancestor-");
        try
        {
            var physicalAncestor = Directory.CreateDirectory(
                Path.Combine(parent.FullName, "physical"));
            var approvedRoot = Directory.CreateDirectory(
                Path.Combine(physicalAncestor.FullName, "repository"));
            await File.WriteAllTextAsync(
                Path.Combine(approvedRoot.FullName, "source.txt"),
                "approved content",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            var linkedAncestor = Path.Combine(
                parent.FullName,
                "linked-ancestor");
            try
            {
                Directory.CreateSymbolicLink(
                    linkedAncestor,
                    physicalAncestor.FullName);
            }
            catch (Exception exception)
                when (exception is IOException
                    or UnauthorizedAccessException
                    or PlatformNotSupportedException)
            {
                return;
            }

            using var context = new FileSystemRepositoryContext(
                Path.Combine(linkedAncestor, "repository"));

            var result = await context.ReadAsync(
                "source.txt",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.True(result.Exists);
            Assert.Null(result.Snippet);
            Assert.Contains(
                result.Diagnostics,
                diagnostic => diagnostic.Code == "SECURITY0002");
        }
        finally
        {
            parent.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Repository_root_replacement_does_not_redirect_later_reads()
    {
        var parent = Directory.CreateTempSubdirectory(
            "sarif-regress-root-replacement-");
        try
        {
            var repositoryPath = Path.Combine(parent.FullName, "repository");
            var retainedRepositoryPath = Path.Combine(
                parent.FullName,
                "retained-repository");
            Directory.CreateDirectory(repositoryPath);
            await File.WriteAllTextAsync(
                Path.Combine(repositoryPath, "source.txt"),
                "approved content",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);

            using (var context = new FileSystemRepositoryContext(
                       repositoryPath))
            {
                Directory.Move(repositoryPath, retainedRepositoryPath);
                Directory.CreateDirectory(repositoryPath);
                await File.WriteAllTextAsync(
                    Path.Combine(repositoryPath, "source.txt"),
                    "replacement content",
                    Encoding.UTF8,
                    TestContext.Current.CancellationToken);

                var result = await context.ReadAsync(
                    "source.txt",
                    new Region(1, null, null, null),
                    lineRadius: 0,
                    cancellationToken:
                        TestContext.Current.CancellationToken);

                Assert.Equal("approved content", result.Snippet);
                Assert.Empty(result.Diagnostics);
            }
        }
        finally
        {
            parent.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Disposed_repository_context_refuses_later_reads()
    {
        var root = Directory.CreateTempSubdirectory(
            "sarif-regress-disposed-root-");
        try
        {
            var context = new FileSystemRepositoryContext(root.FullName);
            context.Dispose();
            context.Dispose();

            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await context.ReadAsync(
                    "source.txt",
                    new Region(1, null, null, null),
                    lineRadius: 0,
                    cancellationToken:
                        TestContext.Current.CancellationToken));
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Windows_network_and_device_roots_are_rejected()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var networkContext = new FileSystemRepositoryContext(
            @"\\server\share\repository");
        using var deviceContext = new FileSystemRepositoryContext(
            @"\\?\C:\repository");

        var networkResult = await networkContext.ReadAsync(
            "source.txt",
            new Region(1, null, null, null),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var deviceResult = await deviceContext.ReadAsync(
            "source.txt",
            new Region(1, null, null, null),
            lineRadius: 0,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Contains(
            networkResult.Diagnostics,
            diagnostic => diagnostic.Code == "SECURITY0002");
        Assert.Contains(
            deviceResult.Diagnostics,
            diagnostic => diagnostic.Code == "SECURITY0002");
    }

    [Fact]
    public async Task Windows_intermediate_junction_is_rejected()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var parent = Directory.CreateTempSubdirectory(
            "sarif-regress-junction-");
        var junctionPath = Path.Combine(
            parent.FullName,
            "root",
            "nested",
            "junction");
        try
        {
            var root = Directory.CreateDirectory(
                Path.Combine(parent.FullName, "root"));
            Directory.CreateDirectory(
                Path.Combine(root.FullName, "nested"));
            var outside = Directory.CreateDirectory(
                Path.Combine(parent.FullName, "outside"));
            await File.WriteAllTextAsync(
                Path.Combine(outside.FullName, "secret.txt"),
                "outside content",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);

            var commandProcessor = Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.System),
                "cmd.exe");
            var startInfo = new ProcessStartInfo
            {
                FileName = commandProcessor,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("/d");
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add("mklink");
            startInfo.ArgumentList.Add("/J");
            startInfo.ArgumentList.Add(junctionPath);
            startInfo.ArgumentList.Add(outside.FullName);
            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException(
                    "The junction-creation process could not be started.");
            var standardErrorTask = process.StandardError
                .ReadToEndAsync(TestContext.Current.CancellationToken);
            var standardOutputTask = process.StandardOutput
                .ReadToEndAsync(TestContext.Current.CancellationToken);
            await process.WaitForExitAsync(
                TestContext.Current.CancellationToken);
            var standardError = await standardErrorTask;
            var standardOutput = await standardOutputTask;
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"mklink /J failed with exit code {process.ExitCode}: "
                    + standardError
                    + standardOutput);
            }

            var result = await new FileSystemRepositoryContext(
                    root.FullName)
                .ReadAsync(
                    Path.Combine(
                        "nested",
                        "junction",
                        "secret.txt"),
                    new Region(1, null, null, null),
                    lineRadius: 0,
                    cancellationToken:
                        TestContext.Current.CancellationToken);

            Assert.True(result.Exists);
            Assert.Null(result.Snippet);
            Assert.Contains(
                result.Diagnostics,
                diagnostic =>
                    diagnostic.Code == "SECURITY0002"
                    && diagnostic.Stage ==
                        DiagnosticStage.Security);
        }
        finally
        {
            if (Directory.Exists(junctionPath))
            {
                Directory.Delete(junctionPath);
            }

            parent.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Opened_repository_handle_cannot_be_redirected_by_a_later_link()
    {
        var parent = Directory.CreateTempSubdirectory(
            "sarif-regress-handle-anchor-");
        try
        {
            var root = Directory.CreateDirectory(
                Path.Combine(parent.FullName, "root"));
            var outside = Directory.CreateDirectory(
                Path.Combine(parent.FullName, "outside"));
            var sourceDirectory = Directory.CreateDirectory(
                Path.Combine(root.FullName, "nested"));
            var sourcePath = Path.Combine(
                sourceDirectory.FullName,
                "source.txt");
            var retainedPath = Path.Combine(
                sourceDirectory.FullName,
                "retained.txt");
            var outsidePath = Path.Combine(outside.FullName, "secret.txt");
            var capabilityProbe = Path.Combine(root.FullName, "link-probe");
            await File.WriteAllTextAsync(
                sourcePath,
                "approved content",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(
                outsidePath,
                "outside content",
                Encoding.UTF8,
                TestContext.Current.CancellationToken);

            try
            {
                File.CreateSymbolicLink(capabilityProbe, outsidePath);
                File.Delete(capabilityProbe);
            }
            catch (Exception exception)
                when (exception is IOException
                    or UnauthorizedAccessException
                    or PlatformNotSupportedException)
            {
                return;
            }

            var openResult = RepositoryFileHandleOpener.Open(
                root.FullName,
                Path.Combine("nested", "source.txt"));
            await using var sourceStream = Assert.IsType<FileStream>(
                openResult.Stream);

            File.Move(sourcePath, retainedPath);
            File.CreateSymbolicLink(sourcePath, outsidePath);
            using var reader = new StreamReader(
                sourceStream,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true);

            var content = await reader
                .ReadToEndAsync(TestContext.Current.CancellationToken);

            Assert.Equal("approved content", content);
            Assert.Equal(RepositoryFileOpenFailure.None, openResult.Failure);
        }
        finally
        {
            parent.Delete(recursive: true);
        }
    }

    [Fact]
    public void Native_open_errors_have_deterministic_fail_closed_classifications()
    {
        Assert.Equal(
            RepositoryFileOpenFailure.UnsafePath,
            LinuxRepositoryFileOpener.ClassifyError(
                LinuxRepositoryFileOpener.ErrorIsSymbolicLink));
        Assert.Equal(
            RepositoryFileOpenFailure.SafetyUnavailable,
            LinuxRepositoryFileOpener.ClassifyError(
                LinuxRepositoryFileOpener.ErrorNoSystemCall));
        Assert.Equal(
            RepositoryFileOpenFailure.UnsupportedFileType,
            LinuxRepositoryFileOpener.ClassifyError(
                LinuxRepositoryFileOpener.ErrorNoSuchDeviceOrAddress));
        Assert.Equal(
            RepositoryFileOpenFailure.UnsafePath,
            WindowsRepositoryFileOpener.ClassifyStatus(
                WindowsRepositoryFileOpener.StatusReparsePointEncountered,
                WindowsRepositoryFileOpener.ErrorFileNotFound));
        Assert.Equal(
            RepositoryFileOpenFailure.SafetyUnavailable,
            WindowsRepositoryFileOpener.ClassifyError(
                WindowsRepositoryFileOpener.ErrorNotSupported));
        Assert.Equal(
            RepositoryFileOpenFailure.UnsupportedFileType,
            WindowsRepositoryFileOpener.ClassifyStatus(
            WindowsRepositoryFileOpener.StatusFileIsDirectory,
                WindowsRepositoryFileOpener.ErrorAccessDenied));
    }

    [Theory]
    [InlineData(LinuxRepositoryFileOpener.AndrewFileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.AndrewFileSystemKernelMagic)]
    [InlineData(LinuxRepositoryFileOpener.CephFileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.CifsFileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.CodaFileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.FuseFileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.NetworkControlProtocolMagic)]
    [InlineData(LinuxRepositoryFileOpener.NetworkFileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.NinePFileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.ProcFileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.SmbFileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.Smb2FileSystemMagic)]
    [InlineData(LinuxRepositoryFileOpener.SysFileSystemMagic)]
    public void Linux_repository_filesystem_denylist_is_complete(
        long fileSystemMagic)
    {
        Assert.True(
            LinuxRepositoryFileOpener.IsUnsafeFileSystem(
                fileSystemMagic));
    }

    [Fact]
    public async Task Directory_targets_are_rejected_as_non_regular_files()
    {
        var root = Directory.CreateTempSubdirectory("sarif-regress-directory-");
        try
        {
            Directory.CreateDirectory(Path.Combine(root.FullName, "source"));
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "source",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.True(result.Exists);
            Assert.Contains(
                result.Diagnostics,
                diagnostic => diagnostic.Code == "SECURITY0005");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Linux_fifo_targets_are_rejected_without_blocking()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var root = Directory.CreateTempSubdirectory("sarif-regress-fifo-");
        try
        {
            var fifoPath = Path.Combine(root.FullName, "source.pipe");
            var startInfo = new ProcessStartInfo
            {
                FileName = "mkfifo",
                UseShellExecute = false,
            };
            startInfo.ArgumentList.Add(fifoPath);
            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException(
                    "The mkfifo process could not be started.");
            await process.WaitForExitAsync(
                TestContext.Current.CancellationToken);
            Assert.Equal(0, process.ExitCode);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                TestContext.Current.CancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "source.pipe",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: timeout.Token);

            Assert.True(result.Exists);
            Assert.Contains(
                result.Diagnostics,
                diagnostic => diagnostic.Code == "SECURITY0005");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Linux_socket_targets_are_rejected_as_non_regular_files()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var root = Directory.CreateTempSubdirectory("sarif-regress-socket-");
        try
        {
            var socketPath = Path.Combine(root.FullName, "source.socket");
            using var socket = new Socket(
                AddressFamily.Unix,
                SocketType.Stream,
                ProtocolType.Unspecified);
            socket.Bind(new UnixDomainSocketEndPoint(socketPath));
            var context = new FileSystemRepositoryContext(root.FullName);

            var result = await context.ReadAsync(
                "source.socket",
                new Region(1, null, null, null),
                lineRadius: 0,
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.True(result.Exists);
            Assert.Contains(
                result.Diagnostics,
                diagnostic => diagnostic.Code == "SECURITY0005");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }
}

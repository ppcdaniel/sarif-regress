using System.Collections.Immutable;
using System.Text;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;
using SarifRegress.Core.Security;
using SarifRegress.Core.Utility;

namespace SarifRegress.Sarif.Repository;

/// <summary>
/// Reads UTF-8 source files from an approved root without following symbolic links.
/// </summary>
public sealed class FileSystemRepositoryContext : IRepositoryContext
{
    /// <summary>
    /// Gets the source-context hashing algorithm identifier.
    /// </summary>
    public const string ContextAlgorithmVersion = "source-context/v1";

    /// <summary>
    /// Gets the token-window hashing algorithm identifier.
    /// </summary>
    public const string TokenWindowAlgorithmVersion = "token-window/v1";

    private const int ReadBufferBytes = 16 * 1024;
    private static readonly byte[] Utf8ByteOrderMark = [0xEF, 0xBB, 0xBF];
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private readonly string repositoryRoot;
    private readonly RepositoryRootHandle repositoryRootHandle;
    private readonly ResourceLimits limits;
    private readonly StringComparison pathComparison;
    private int disposed;

    /// <summary>
    /// Initializes a bounded repository adapter.
    /// </summary>
    /// <param name="repositoryRoot">The explicitly approved repository root.</param>
    /// <param name="limits">The untrusted-input limits.</param>
    public FileSystemRepositoryContext(
        string repositoryRoot,
        ResourceLimits? limits = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        this.limits = limits ?? ResourceLimits.Default;
        this.limits.Validate();
        this.repositoryRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(repositoryRoot));
        repositoryRootHandle = RepositoryFileHandleOpener.OpenRoot(
            this.repositoryRoot);
        pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
    }

    /// <inheritdoc />
    public async ValueTask<RepositoryContextResult> ReadAsync(
        string repositoryRelativePath,
        Region? region,
        int lineRadius,
        SourceReference? sourceReference = null,
        CancellationToken cancellationToken = default,
        bool includeTokenWindow = false)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref disposed) != 0,
            this);
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRelativePath);
        if (lineRadius < 0 || lineRadius > limits.MaximumSnippetRadius)
        {
            throw new ArgumentOutOfRangeException(
                nameof(lineRadius),
                lineRadius,
                $"The line radius must be between 0 and {limits.MaximumSnippetRadius}.");
        }

        var diagnostics = new List<Diagnostic>();
        if (!TryResolveContainedPath(
                repositoryRelativePath,
                sourceReference,
                diagnostics,
                out var safeRelativePath))
        {
            return CreateResult(exists: false, null, null, diagnostics);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var openResult = repositoryRootHandle.Open(safeRelativePath);
        if (openResult.Stream is not FileStream sourceStream)
        {
            return CreateOpenFailureResult(
                openResult.Failure,
                sourceReference,
                diagnostics);
        }

        byte[] sourceBytes;
        try
        {
            await using (sourceStream.ConfigureAwait(false))
            {
                sourceBytes = await ReadBoundedAsync(
                        sourceStream,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (RepositoryFileLimitExceededException)
        {
            diagnostics.Add(
                new Diagnostic(
                    "SECURITY0003",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    $"The source file exceeds the configured {limits.MaximumRepositoryFileBytes}-byte limit.",
                    sourceReference));
            return CreateResult(exists: true, null, null, diagnostics);
        }
        catch (IOException)
        {
            diagnostics.Add(
                new Diagnostic(
                    "IO0002",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Repository,
                    "The source file could not be read.",
                    sourceReference));
            return CreateResult(exists: true, null, null, diagnostics);
        }
        catch (UnauthorizedAccessException)
        {
            diagnostics.Add(
                new Diagnostic(
                    "IO0003",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Repository,
                    "Access to the source file was denied.",
                    sourceReference));
            return CreateResult(exists: true, null, null, diagnostics);
        }
        catch (NotSupportedException)
        {
            diagnostics.Add(CreateUnsupportedFileTypeDiagnostic(sourceReference));
            return CreateResult(exists: true, null, null, diagnostics);
        }

        string sourceText;
        try
        {
            var content = sourceBytes.AsSpan();
            if (content.StartsWith(Utf8ByteOrderMark))
            {
                content = content[Utf8ByteOrderMark.Length..];
            }

            sourceText = StrictUtf8.GetString(content);
        }
        catch (DecoderFallbackException)
        {
            diagnostics.Add(
                new Diagnostic(
                    "IO0004",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Repository,
                    "The source file is not valid UTF-8.",
                    sourceReference));
            return CreateResult(exists: true, null, null, diagnostics);
        }

        var normalizedText = NormalizeLineEndings(sourceText);
        if (region?.StartLine is not int startLine)
        {
            return CreateResult(exists: true, null, null, diagnostics);
        }

        var lines = normalizedText.Split('\n');
        if (startLine > lines.Length)
        {
            diagnostics.Add(
                new Diagnostic(
                    "CANON0010",
                    DiagnosticSeverity.Warning,
                    DiagnosticStage.Repository,
                    "The SARIF start line is outside the bounded source file.",
                    sourceReference));
            return CreateResult(exists: true, null, null, diagnostics);
        }

        var endLine = region.EndLine ?? startLine;
        var firstIncludedLine = (int)Math.Max(
            1L,
            (long)startLine - lineRadius);
        var lastIncludedLine = (int)Math.Min(
            lines.Length,
            (long)endLine + lineRadius);
        var snippet = string.Join(
            '\n',
            lines[(firstIncludedLine - 1)..lastIncludedLine]);
        var snippetHash = VersionedHash.Compute(
            ContextAlgorithmVersion,
            snippet);
        string? tokenWindowHash = null;
        if (includeTokenWindow)
        {
            var tokenWindow = TokenWindowCanonicalizer.Create(
                normalizedText,
                startLine,
                (int)Math.Min((long)lines.Length, endLine),
                limits,
                cancellationToken);
            tokenWindowHash = tokenWindow.Hash;
            if (tokenWindow.Refusal is TokenWindowRefusal.TooManyRegionTerms)
            {
                diagnostics.Add(
                    new Diagnostic(
                        "CANON0011",
                        DiagnosticSeverity.Warning,
                        DiagnosticStage.Canonicalisation,
                        $"The source region exceeds the configured {limits.MaximumTokenWindowTerms}-term token-window limit; token evidence was omitted.",
                        sourceReference));
            }
            else if (tokenWindow.Refusal is TokenWindowRefusal.TermTooLong)
            {
                diagnostics.Add(
                    new Diagnostic(
                        "CANON0012",
                        DiagnosticSeverity.Warning,
                        DiagnosticStage.Canonicalisation,
                        $"A source token exceeds the configured {limits.MaximumStringCharacters}-character limit; token evidence was omitted.",
                        sourceReference));
            }
        }

        var evidence = new ContextEvidence(
            snippetHash,
            tokenWindowHash,
            EnclosingSymbol: null,
            firstIncludedLine,
            lastIncludedLine);

        return CreateResult(exists: true, snippet, evidence, diagnostics);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        repositoryRootHandle.Dispose();
    }

    private bool TryResolveContainedPath(
        string repositoryRelativePath,
        SourceReference? sourceReference,
        ICollection<Diagnostic> diagnostics,
        out string safeRelativePath)
    {
        safeRelativePath = string.Empty;
        var normalizedRelativePath = repositoryRelativePath
            .Replace('\\', Path.DirectorySeparatorChar)
            .Replace('/', Path.DirectorySeparatorChar);
        if (Path.IsPathRooted(normalizedRelativePath))
        {
            diagnostics.Add(CreateContainmentDiagnostic(sourceReference));
            return false;
        }

        string sourcePath;
        try
        {
            sourcePath = Path.GetFullPath(
                Path.Combine(repositoryRoot, normalizedRelativePath));
        }
        catch (Exception exception)
            when (exception is ArgumentException
                or NotSupportedException
                or PathTooLongException)
        {
            diagnostics.Add(CreateContainmentDiagnostic(sourceReference));
            return false;
        }

        var relativeToRoot = Path.GetRelativePath(repositoryRoot, sourcePath);
        if (relativeToRoot == ".." ||
            relativeToRoot.StartsWith(
                $"..{Path.DirectorySeparatorChar}",
                pathComparison) ||
            Path.IsPathRooted(relativeToRoot))
        {
            diagnostics.Add(CreateContainmentDiagnostic(sourceReference));
            return false;
        }

        safeRelativePath = relativeToRoot;
        return true;
    }

    private async Task<byte[]> ReadBoundedAsync(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        if (stream.Length > limits.MaximumRepositoryFileBytes)
        {
            throw new RepositoryFileLimitExceededException();
        }

        using var content = new MemoryStream(
            capacity: (int)Math.Min(stream.Length, ReadBufferBytes));
        var buffer = new byte[ReadBufferBytes];
        long totalBytes = 0;
        while (true)
        {
            var bytesRead = await stream
                .ReadAsync(buffer, cancellationToken)
                .ConfigureAwait(false);
            if (bytesRead == 0)
            {
                return content.ToArray();
            }

            totalBytes += bytesRead;
            if (totalBytes > limits.MaximumRepositoryFileBytes)
            {
                throw new RepositoryFileLimitExceededException();
            }

            await content
                .WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static string NormalizeLineEndings(string value) =>
        value
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');

    private static Diagnostic CreateContainmentDiagnostic(
        SourceReference? sourceReference) =>
        new(
            "SECURITY0001",
            DiagnosticSeverity.Error,
            DiagnosticStage.Security,
            "Repository context rejected a path outside the approved root.",
            sourceReference,
            help: "Supply a canonical repository-relative path without parent traversal.");

    private static RepositoryContextResult CreateOpenFailureResult(
        RepositoryFileOpenFailure failure,
        SourceReference? sourceReference,
        ICollection<Diagnostic> diagnostics)
    {
        var diagnostic = failure switch
        {
            RepositoryFileOpenFailure.NotFound => new Diagnostic(
                "IO0001",
                DiagnosticSeverity.Note,
                DiagnosticStage.Repository,
                "The canonical repository path does not exist.",
                sourceReference),
            RepositoryFileOpenFailure.UnsafePath => new Diagnostic(
                "SECURITY0002",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                "Repository context rejected a symbolic link or reparse point.",
                sourceReference,
                help: "Use a regular file contained directly within the approved repository root."),
            RepositoryFileOpenFailure.UnsupportedFileType =>
                CreateUnsupportedFileTypeDiagnostic(sourceReference),
            RepositoryFileOpenFailure.AccessDenied => new Diagnostic(
                "IO0003",
                DiagnosticSeverity.Error,
                DiagnosticStage.Repository,
                "Access to the source file was denied.",
                sourceReference),
            RepositoryFileOpenFailure.SafetyUnavailable => new Diagnostic(
                "SECURITY0004",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                "Repository context could not preserve handle-anchored symbolic-link containment.",
                sourceReference,
                help: "Use Windows or x64/Arm64 Linux with openat2 and statx containment."),
            _ => new Diagnostic(
                "IO0002",
                DiagnosticSeverity.Error,
                DiagnosticStage.Repository,
                "The source file could not be read.",
                sourceReference),
        };
        diagnostics.Add(diagnostic);
        return CreateResult(
            exists: failure is not RepositoryFileOpenFailure.NotFound,
            null,
            null,
            diagnostics);
    }

    private static Diagnostic CreateUnsupportedFileTypeDiagnostic(
        SourceReference? sourceReference) =>
        new(
            "SECURITY0005",
            DiagnosticSeverity.Error,
            DiagnosticStage.Security,
            "Repository context rejected a non-regular source file.",
            sourceReference,
            help: "Use a regular file rather than a directory, device, socket, or named pipe.");

    private static RepositoryContextResult CreateResult(
        bool exists,
        string? snippet,
        ContextEvidence? evidence,
        IEnumerable<Diagnostic> diagnostics) =>
        new(exists, snippet, evidence, Diagnostic.Sort(diagnostics));

    private sealed class RepositoryFileLimitExceededException : IOException
    {
    }
}

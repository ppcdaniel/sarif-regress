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
    private readonly ResourceLimits limits;
    private readonly StringComparison pathComparison;

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
        this.repositoryRoot = Path.GetFullPath(repositoryRoot);
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
                out var sourcePath))
        {
            return CreateResult(exists: false, null, null, diagnostics);
        }

        if (!File.Exists(sourcePath))
        {
            diagnostics.Add(
                new Diagnostic(
                    "IO0001",
                    DiagnosticSeverity.Note,
                    DiagnosticStage.Repository,
                    "The canonical repository path does not exist.",
                    sourceReference));
            return CreateResult(exists: false, null, null, diagnostics);
        }

        if (!TryContainsReparsePoint(sourcePath, out var containsReparsePoint))
        {
            diagnostics.Add(
                new Diagnostic(
                    "SECURITY0004",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    "Repository context could not verify symbolic-link containment.",
                    sourceReference,
                    help: "Ensure every path component is readable and contained within the approved repository root."));
            return CreateResult(exists: true, null, null, diagnostics);
        }

        if (containsReparsePoint)
        {
            diagnostics.Add(
                new Diagnostic(
                    "SECURITY0002",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    "Repository context rejected a symbolic link or reparse point.",
                    sourceReference,
                    help: "Use a regular file contained directly within the approved repository root."));
            return CreateResult(exists: true, null, null, diagnostics);
        }

        byte[] sourceBytes;
        try
        {
            sourceBytes = await ReadBoundedAsync(sourcePath, cancellationToken)
                .ConfigureAwait(false);
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
        catch (RepositoryPathSafetyException)
        {
            diagnostics.Add(
                new Diagnostic(
                    "SECURITY0004",
                    DiagnosticSeverity.Error,
                    DiagnosticStage.Security,
                    "Repository context could not preserve symbolic-link containment while reading.",
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

    private bool TryResolveContainedPath(
        string repositoryRelativePath,
        SourceReference? sourceReference,
        ICollection<Diagnostic> diagnostics,
        out string sourcePath)
    {
        sourcePath = string.Empty;
        var normalizedRelativePath = repositoryRelativePath
            .Replace('\\', Path.DirectorySeparatorChar)
            .Replace('/', Path.DirectorySeparatorChar);
        if (Path.IsPathRooted(normalizedRelativePath))
        {
            diagnostics.Add(CreateContainmentDiagnostic(sourceReference));
            return false;
        }

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
            sourcePath = string.Empty;
            return false;
        }

        return true;
    }

    private bool TryContainsReparsePoint(
        string sourcePath,
        out bool containsReparsePoint)
    {
        containsReparsePoint = false;
        if (!TryHasReparsePoint(repositoryRoot, out var rootIsReparsePoint))
        {
            return false;
        }

        if (rootIsReparsePoint)
        {
            containsReparsePoint = true;
            return true;
        }

        var relativePath = Path.GetRelativePath(repositoryRoot, sourcePath);
        var currentPath = repositoryRoot;
        foreach (var segment in relativePath.Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            currentPath = Path.Combine(currentPath, segment);
            if (!TryHasReparsePoint(currentPath, out var isReparsePoint))
            {
                return false;
            }

            if (isReparsePoint)
            {
                containsReparsePoint = true;
                return true;
            }
        }

        return true;
    }

    private async Task<byte[]> ReadBoundedAsync(
        string sourcePath,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            ReadBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (!TryContainsReparsePoint(sourcePath, out var containsReparsePoint) ||
            containsReparsePoint)
        {
            throw new RepositoryPathSafetyException();
        }

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
                if (!TryContainsReparsePoint(
                        sourcePath,
                        out containsReparsePoint) ||
                    containsReparsePoint)
                {
                    throw new RepositoryPathSafetyException();
                }

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

    private static bool TryHasReparsePoint(
        string path,
        out bool isReparsePoint)
    {
        try
        {
            isReparsePoint =
                (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
            return true;
        }
        catch (IOException)
        {
            isReparsePoint = false;
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            isReparsePoint = false;
            return false;
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

    private static RepositoryContextResult CreateResult(
        bool exists,
        string? snippet,
        ContextEvidence? evidence,
        IEnumerable<Diagnostic> diagnostics) =>
        new(exists, snippet, evidence, Diagnostic.Sort(diagnostics));

    private sealed class RepositoryFileLimitExceededException : IOException
    {
    }

    private sealed class RepositoryPathSafetyException : IOException
    {
    }
}

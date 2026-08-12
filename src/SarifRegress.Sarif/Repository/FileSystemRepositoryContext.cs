using System.Collections.Immutable;
using System.Security.Cryptography;
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

    /// <summary>
    /// Gets the trusted comment-blind lexical-context algorithm identifier.
    /// </summary>
    public const string TrustedLexicalContextAlgorithmVersion =
        "trusted-lexical-context/v1";

    private const int ReadBufferBytes = 16 * 1024;
    private static readonly byte[] Utf8ByteOrderMark = [0xEF, 0xBB, 0xBF];
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private readonly string repositoryRoot;
    private readonly RepositoryRootHandle repositoryRootHandle;
    private readonly ResourceLimits limits;
    private readonly StringComparison pathComparison;
    private readonly RepositorySnapshotManifest? snapshotManifest;
    private readonly Dictionary<string, TrustedSnapshotCacheEntry>?
        verifiedSnapshotFiles;
    private readonly SemaphoreSlim? snapshotReadGate;
    private long cachedSnapshotRetainedBytes;
    private bool snapshotCacheExhausted;
    private int trustedSnapshotFileVerificationCount;
    private int trustedSnapshotIndexBuildCount;
    private int disposed;

    /// <summary>
    /// Initializes a bounded repository adapter.
    /// </summary>
    /// <param name="repositoryRoot">The explicitly approved repository root.</param>
    /// <param name="limits">The untrusted-input limits.</param>
    public FileSystemRepositoryContext(
        string repositoryRoot,
        ResourceLimits? limits = null)
        : this(
            repositoryRoot,
            snapshotManifest: null,
            limits,
            initializeSnapshotCache: false)
    {
    }

    /// <summary>
    /// Initializes a bounded repository adapter bound to an independently trusted snapshot.
    /// </summary>
    /// <param name="repositoryRoot">The explicitly approved repository root.</param>
    /// <param name="snapshotManifest">
    /// The exact raw-byte digests that admit source files into this snapshot.
    /// </param>
    /// <param name="limits">The untrusted-input limits.</param>
    public FileSystemRepositoryContext(
        string repositoryRoot,
        RepositorySnapshotManifest snapshotManifest,
        ResourceLimits? limits = null)
        : this(
            repositoryRoot,
            snapshotManifest ?? throw new ArgumentNullException(
                nameof(snapshotManifest)),
            limits,
            initializeSnapshotCache: true)
    {
    }

    private FileSystemRepositoryContext(
        string repositoryRoot,
        RepositorySnapshotManifest? snapshotManifest,
        ResourceLimits? limits,
        bool initializeSnapshotCache)
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
        this.snapshotManifest = snapshotManifest;
        if (initializeSnapshotCache)
        {
            verifiedSnapshotFiles =
                new Dictionary<string, TrustedSnapshotCacheEntry>(
                StringComparer.Ordinal);
            snapshotReadGate = new SemaphoreSlim(1, 1);
        }
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

        if (snapshotManifest is not null)
        {
            if (!RepositorySnapshotPath.IsCanonicalAsciiRelativePath(
                    repositoryRelativePath) ||
                !snapshotManifest.TryGetExpectedSha256(
                    repositoryRelativePath,
                    out var expectedSha256))
            {
                diagnostics.Add(
                    new Diagnostic(
                        "SECURITY0008",
                        DiagnosticSeverity.Error,
                        DiagnosticStage.Security,
                        "The trusted repository snapshot does not admit this canonical repository-relative path.",
                        sourceReference));
                return CreateResult(
                    exists: false,
                    null,
                    null,
                    diagnostics);
            }

            var verifiedSourceResult = await ReadVerifiedSnapshotFileAsync(
                    safeRelativePath,
                    repositoryRelativePath,
                    expectedSha256,
                    sourceReference,
                    diagnostics,
                    cancellationToken)
                .ConfigureAwait(false);
            if (verifiedSourceResult.SourceFile is not
                TrustedSnapshotSourceFile verifiedSourceFile)
            {
                return CreateResult(
                    verifiedSourceResult.Exists,
                    null,
                    null,
                    diagnostics);
            }

            return CreateTrustedEvidenceResult(
                verifiedSourceFile,
                region,
                lineRadius,
                sourceReference,
                diagnostics,
                cancellationToken);
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
        return CreateEvidenceResult(
            normalizedText,
            region,
            lineRadius,
            sourceReference,
            includeTokenWindow,
            diagnostics,
            cancellationToken);
    }

    /// <summary>
    /// Gets the number of whole-file trusted lexical indexes built by this context.
    /// </summary>
    /// <remarks>This observable is internal so adversarial tests can enforce the work bound.</remarks>
    internal int TrustedSnapshotIndexBuildCount =>
        Volatile.Read(ref trustedSnapshotIndexBuildCount);

    /// <summary>
    /// Gets the number of physical snapshot files opened for verification.
    /// </summary>
    internal int TrustedSnapshotFileVerificationCount =>
        Volatile.Read(ref trustedSnapshotFileVerificationCount);

    private RepositoryContextResult CreateTrustedEvidenceResult(
        TrustedSnapshotSourceFile sourceFile,
        Region? region,
        int lineRadius,
        SourceReference? sourceReference,
        ICollection<Diagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (region?.StartLine is not int startLine)
        {
            return CreateResult(exists: true, null, null, diagnostics);
        }

        if (startLine > sourceFile.LineCount)
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
            sourceFile.LineCount,
            (long)endLine + lineRadius);
        var snippet = sourceFile.GetSnippet(
            firstIncludedLine,
            lastIncludedLine);
        var evidence = new ContextEvidence(
            SnippetHash: null,
            TokenWindowHash: null,
            EnclosingSymbol: null,
            firstIncludedLine,
            lastIncludedLine);
        var trustedLexicalContextHash =
            region.EndLine is int explicitEndLine &&
                explicitEndLine != startLine
                ? null
                : sourceFile.GetLexicalContext(startLine).Hash;

        return CreateResult(exists: true, snippet, evidence, diagnostics) with
        {
            TrustedLexicalContextHash = trustedLexicalContextHash,
        };
    }

    private RepositoryContextResult CreateEvidenceResult(
        string normalizedText,
        Region? region,
        int lineRadius,
        SourceReference? sourceReference,
        bool includeTokenWindow,
        ICollection<Diagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
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
        snapshotReadGate?.Dispose();
    }

    // Time: O(file bytes). Space: O(file bytes + the bounded immutable cache).
    private async ValueTask<VerifiedSourceReadResult>
        ReadVerifiedSnapshotFileAsync(
            string safeRelativePath,
            string canonicalRepositoryRelativePath,
            string expectedSha256,
            SourceReference? sourceReference,
            ICollection<Diagnostic> diagnostics,
            CancellationToken cancellationToken)
    {
        await snapshotReadGate!
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (verifiedSnapshotFiles!.TryGetValue(
                    canonicalRepositoryRelativePath,
                    out var cachedEntry))
            {
                if (cachedEntry.SourceFile is not
                    TrustedSnapshotSourceFile cachedSourceFile)
                {
                    diagnostics.Add(
                        CreateSnapshotFailureDiagnostic(
                            cachedEntry.Failure,
                            sourceReference));
                    return new VerifiedSourceReadResult(
                        cachedEntry.Exists,
                        SourceFile: null);
                }

                return new VerifiedSourceReadResult(
                    Exists: true,
                    cachedSourceFile);
            }

            if (snapshotCacheExhausted)
            {
                return CacheSnapshotFailure(
                    canonicalRepositoryRelativePath,
                    exists: true,
                    CachedSnapshotFailure.CacheBudgetExceeded,
                    sourceReference,
                    diagnostics);
            }

            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(
                ref trustedSnapshotFileVerificationCount);
            var openResult = repositoryRootHandle.Open(safeRelativePath);
            if (openResult.Stream is not FileStream sourceStream)
            {
                return CacheSnapshotFailure(
                    canonicalRepositoryRelativePath,
                    exists: openResult.Failure is not
                        RepositoryFileOpenFailure.NotFound,
                    MapSnapshotOpenFailure(openResult.Failure),
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
                return CacheSnapshotFailure(
                    canonicalRepositoryRelativePath,
                    exists: true,
                    CachedSnapshotFailure.FileTooLarge,
                    sourceReference,
                    diagnostics);
            }
            catch (IOException)
            {
                return CacheSnapshotFailure(
                    canonicalRepositoryRelativePath,
                    exists: true,
                    CachedSnapshotFailure.ReadFailure,
                    sourceReference,
                    diagnostics);
            }
            catch (UnauthorizedAccessException)
            {
                return CacheSnapshotFailure(
                    canonicalRepositoryRelativePath,
                    exists: true,
                    CachedSnapshotFailure.AccessDenied,
                    sourceReference,
                    diagnostics);
            }
            catch (NotSupportedException)
            {
                return CacheSnapshotFailure(
                    canonicalRepositoryRelativePath,
                    exists: true,
                    CachedSnapshotFailure.UnsupportedFileType,
                    sourceReference,
                    diagnostics);
            }

            var actualSha256 = Convert
                .ToHexString(SHA256.HashData(sourceBytes))
                .ToLowerInvariant();
            if (!string.Equals(
                    actualSha256,
                    expectedSha256,
                    StringComparison.Ordinal))
            {
                return CacheSnapshotFailure(
                    canonicalRepositoryRelativePath,
                    exists: true,
                    CachedSnapshotFailure.DigestMismatch,
                    sourceReference,
                    diagnostics);
            }

            string normalizedText;
            try
            {
                var content = sourceBytes.AsSpan();
                if (content.StartsWith(Utf8ByteOrderMark))
                {
                    content = content[Utf8ByteOrderMark.Length..];
                }

                normalizedText = NormalizeLineEndings(
                    StrictUtf8.GetString(content));
            }
            catch (DecoderFallbackException)
            {
                return CacheSnapshotFailure(
                    canonicalRepositoryRelativePath,
                    exists: true,
                    CachedSnapshotFailure.InvalidUtf8,
                    sourceReference,
                    diagnostics);
            }

            var remainingCacheBytes =
                limits.MaximumInputBytes - cachedSnapshotRetainedBytes;
            var sourceFileCreation = TrustedSnapshotSourceFile.Create(
                normalizedText,
                remainingCacheBytes,
                limits,
                cancellationToken);
            if (sourceFileCreation.SourceFile is not
                TrustedSnapshotSourceFile sourceFile)
            {
                // A closed cache bounds aggregate verification work as well as retained memory.
                // Continuing to open distinct files after the first overflow could otherwise
                // perform MaximumRunCollectionItems whole-file reads that can never be retained.
                snapshotCacheExhausted = true;
                return CacheSnapshotFailure(
                    canonicalRepositoryRelativePath,
                    exists: true,
                    CachedSnapshotFailure.CacheBudgetExceeded,
                    sourceReference,
                    diagnostics);
            }

            verifiedSnapshotFiles.Add(
                canonicalRepositoryRelativePath,
                new TrustedSnapshotCacheEntry(
                    Exists: true,
                    sourceFile,
                    CachedSnapshotFailure.None));
            cachedSnapshotRetainedBytes += sourceFile.RetainedByteCount;
            Interlocked.Increment(ref trustedSnapshotIndexBuildCount);
            return new VerifiedSourceReadResult(
                Exists: true,
                sourceFile);
        }
        finally
        {
            snapshotReadGate.Release();
        }
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

    private VerifiedSourceReadResult CacheSnapshotFailure(
        string canonicalRepositoryRelativePath,
        bool exists,
        CachedSnapshotFailure failure,
        SourceReference? sourceReference,
        ICollection<Diagnostic> diagnostics)
    {
        verifiedSnapshotFiles!.Add(
            canonicalRepositoryRelativePath,
            new TrustedSnapshotCacheEntry(
                exists,
                SourceFile: null,
                failure));
        diagnostics.Add(
            CreateSnapshotFailureDiagnostic(failure, sourceReference));
        return new VerifiedSourceReadResult(exists, SourceFile: null);
    }

    private static CachedSnapshotFailure MapSnapshotOpenFailure(
        RepositoryFileOpenFailure failure) =>
        failure switch
        {
            RepositoryFileOpenFailure.NotFound =>
                CachedSnapshotFailure.NotFound,
            RepositoryFileOpenFailure.UnsafePath =>
                CachedSnapshotFailure.UnsafePath,
            RepositoryFileOpenFailure.UnsupportedFileType =>
                CachedSnapshotFailure.UnsupportedFileType,
            RepositoryFileOpenFailure.AccessDenied =>
                CachedSnapshotFailure.AccessDenied,
            RepositoryFileOpenFailure.SafetyUnavailable =>
                CachedSnapshotFailure.SafetyUnavailable,
            _ => CachedSnapshotFailure.ReadFailure,
        };

    private Diagnostic CreateSnapshotFailureDiagnostic(
        CachedSnapshotFailure failure,
        SourceReference? sourceReference) =>
        failure switch
        {
            CachedSnapshotFailure.NotFound => new Diagnostic(
                "IO0001",
                DiagnosticSeverity.Note,
                DiagnosticStage.Repository,
                "The canonical repository path does not exist.",
                sourceReference),
            CachedSnapshotFailure.UnsafePath => new Diagnostic(
                "SECURITY0002",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                "Repository context rejected a symbolic link or reparse point.",
                sourceReference,
                help: "Use a regular file contained directly within the approved repository root."),
            CachedSnapshotFailure.UnsupportedFileType =>
                CreateUnsupportedFileTypeDiagnostic(sourceReference),
            CachedSnapshotFailure.AccessDenied => new Diagnostic(
                "IO0003",
                DiagnosticSeverity.Error,
                DiagnosticStage.Repository,
                "Access to the source file was denied.",
                sourceReference),
            CachedSnapshotFailure.SafetyUnavailable => new Diagnostic(
                "SECURITY0004",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                "Repository context could not preserve handle-anchored symbolic-link containment.",
                sourceReference,
                help: "Use Windows or x64/Arm64 Linux with openat2 and statx containment."),
            CachedSnapshotFailure.FileTooLarge => new Diagnostic(
                "SECURITY0003",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                $"The source file exceeds the configured {limits.MaximumRepositoryFileBytes}-byte limit.",
                sourceReference),
            CachedSnapshotFailure.DigestMismatch => new Diagnostic(
                "SECURITY0009",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                "The source file raw-byte SHA-256 does not match the trusted repository snapshot manifest.",
                sourceReference),
            CachedSnapshotFailure.InvalidUtf8 => new Diagnostic(
                "IO0004",
                DiagnosticSeverity.Error,
                DiagnosticStage.Repository,
                "The source file is not valid UTF-8.",
                sourceReference),
            CachedSnapshotFailure.CacheBudgetExceeded => new Diagnostic(
                "SECURITY0014",
                DiagnosticSeverity.Error,
                DiagnosticStage.Security,
                $"The immutable repository snapshot cache exceeds the configured {limits.MaximumInputBytes}-byte input limit.",
                sourceReference),
            _ => new Diagnostic(
                "IO0002",
                DiagnosticSeverity.Error,
                DiagnosticStage.Repository,
                "The source file could not be read.",
                sourceReference),
        };

    private sealed class RepositoryFileLimitExceededException : IOException
    {
    }

    private readonly record struct VerifiedSourceReadResult(
        bool Exists,
        TrustedSnapshotSourceFile? SourceFile);

    private readonly record struct TrustedSnapshotCacheEntry(
        bool Exists,
        TrustedSnapshotSourceFile? SourceFile,
        CachedSnapshotFailure Failure);

    private enum CachedSnapshotFailure
    {
        None,
        NotFound,
        UnsafePath,
        UnsupportedFileType,
        AccessDenied,
        SafetyUnavailable,
        ReadFailure,
        FileTooLarge,
        DigestMismatch,
        InvalidUtf8,
        CacheBudgetExceeded,
    }
}

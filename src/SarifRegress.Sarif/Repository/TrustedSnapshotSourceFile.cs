using SarifRegress.Core.Security;

namespace SarifRegress.Sarif.Repository;

/// <summary>
/// Holds the immutable, verified representation used by trusted snapshot reads.
/// </summary>
internal sealed class TrustedSnapshotSourceFile
{
    private const int EstimatedArrayObjectBytes = 32;
    private const int EstimatedLexicalResultSlotBytes = 16;
    private const int EstimatedStringCharacterBytes = sizeof(char);
    private const int EstimatedStoredHashBytes = 160;

    private readonly string normalizedText;
    private readonly int[] lineStarts;
    private readonly TrustedLexicalContextResult[] lexicalContextByLine;

    private TrustedSnapshotSourceFile(
        string normalizedText,
        int[] lineStarts,
        TrustedLexicalContextResult[] lexicalContextByLine,
        long retainedByteCount)
    {
        this.normalizedText = normalizedText;
        this.lineStarts = lineStarts;
        this.lexicalContextByLine = lexicalContextByLine;
        RetainedByteCount = retainedByteCount;
    }

    /// <summary>
    /// Gets the deterministic upper-bound accounting charged to the snapshot cache.
    /// </summary>
    public long RetainedByteCount { get; }

    /// <summary>
    /// Gets the number of logical lines, including the empty line after a final LF.
    /// </summary>
    public int LineCount => lineStarts.Length;

    /// <summary>
    /// Creates a bounded immutable source model.
    /// </summary>
    /// <remarks>
    /// Time: O(file characters). Space: O(file characters + line count).
    /// </remarks>
    public static TrustedSnapshotSourceFileCreationResult Create(
        string normalizedText,
        long maximumRetainedBytes,
        ResourceLimits limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(normalizedText);
        ArgumentNullException.ThrowIfNull(limits);
        cancellationToken.ThrowIfCancellationRequested();

        var lineCount = CountLines(normalizedText, cancellationToken);
        var baseRetainedBytes = CalculateBaseRetainedBytes(
            normalizedText.Length,
            lineCount);
        if (baseRetainedBytes > maximumRetainedBytes)
        {
            return TrustedSnapshotSourceFileCreationResult.Refused;
        }

        var maximumStoredHashes = (int)Math.Min(
            int.MaxValue,
            (maximumRetainedBytes - baseRetainedBytes) /
                EstimatedStoredHashBytes);
        var lexicalIndex = TrustedLexicalContextCanonicalizer.CreateIndex(
            normalizedText,
            lineCount,
            maximumStoredHashes,
            limits,
            cancellationToken);
        if (lexicalIndex.Results is null)
        {
            return TrustedSnapshotSourceFileCreationResult.Refused;
        }

        var lineStarts = CreateLineStarts(
            normalizedText,
            lineCount,
            cancellationToken);
        var retainedByteCount = checked(
            baseRetainedBytes +
            ((long)lexicalIndex.StoredHashCount *
                EstimatedStoredHashBytes));
        return new TrustedSnapshotSourceFileCreationResult(
            new TrustedSnapshotSourceFile(
                normalizedText,
                lineStarts,
                lexicalIndex.Results,
                retainedByteCount));
    }

    /// <summary>
    /// Extracts an inclusive line range without allocating a whole-file line array.
    /// </summary>
    /// <remarks>Time: O(snippet characters). Space: O(snippet characters).</remarks>
    public string GetSnippet(int firstLine, int lastLine)
    {
        if (firstLine < 1 ||
            lastLine < firstLine ||
            lastLine > LineCount)
        {
            throw new ArgumentOutOfRangeException(nameof(firstLine));
        }

        var startOffset = lineStarts[firstLine - 1];
        var endOffset = lastLine == LineCount
            ? normalizedText.Length
            : lineStarts[lastLine] - 1;
        return normalizedText.Substring(
            startOffset,
            endOffset - startOffset);
    }

    /// <summary>
    /// Gets the precomputed trusted lexical result for one line.
    /// </summary>
    /// <remarks>Time: O(1). Space: O(1).</remarks>
    public TrustedLexicalContextResult GetLexicalContext(int line)
    {
        if (line < 1 || line > LineCount)
        {
            throw new ArgumentOutOfRangeException(nameof(line));
        }

        return lexicalContextByLine[line - 1];
    }

    private static int CountLines(
        string normalizedText,
        CancellationToken cancellationToken)
    {
        var lineCount = 1;
        for (var offset = 0; offset < normalizedText.Length; offset++)
        {
            if ((offset & 1023) == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            if (normalizedText[offset] == '\n')
            {
                lineCount++;
            }
        }

        return lineCount;
    }

    private static int[] CreateLineStarts(
        string normalizedText,
        int lineCount,
        CancellationToken cancellationToken)
    {
        var lineStarts = new int[lineCount];
        var lineIndex = 1;
        for (var offset = 0; offset < normalizedText.Length; offset++)
        {
            if ((offset & 1023) == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            if (normalizedText[offset] == '\n')
            {
                lineStarts[lineIndex++] = offset + 1;
            }
        }

        return lineStarts;
    }

    private static long CalculateBaseRetainedBytes(
        int characterCount,
        int lineCount) =>
        checked(
            (3L * EstimatedArrayObjectBytes) +
            ((long)characterCount * EstimatedStringCharacterBytes) +
            ((long)lineCount * sizeof(int)) +
            ((long)lineCount * EstimatedLexicalResultSlotBytes));
}

internal readonly record struct TrustedSnapshotSourceFileCreationResult(
    TrustedSnapshotSourceFile? SourceFile)
{
    public static TrustedSnapshotSourceFileCreationResult Refused { get; } =
        new(SourceFile: null);
}

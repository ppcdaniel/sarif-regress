using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;

namespace SarifRegress.Validation;

/// <summary>Reports canonical source-tree hashes for the frozen tree and current index.</summary>
public sealed record SourceTreeHashResult(
    string FrozenCommitSha256,
    string CurrentIndexSha256);

/// <summary>
/// Hashes exact tracked Git blob bytes with ordinal repository-relative paths and length prefixes.
/// </summary>
public sealed class GitSourceTreeHasher
{
    private static readonly byte[] AlgorithmPrefix =
        Encoding.ASCII.GetBytes("sarifregress/source-tree/v1\0");

    private readonly BoundedProcessRunner processRunner;
    private readonly ValidationLimits limits;

    /// <summary>Creates a Git-backed source-tree hasher.</summary>
    public GitSourceTreeHasher(
        BoundedProcessRunner? processRunner = null,
        ValidationLimits? limits = null)
    {
        this.processRunner = processRunner ?? new BoundedProcessRunner();
        this.limits = limits ?? ValidationLimits.Default;
    }

    /// <summary>
    /// Time: O(total tracked source bytes + n log n); Space: O(n) entries plus one blob.
    /// </summary>
    public async ValueTask<SourceTreeHashResult> ComputeAsync(
        string repositoryRoot,
        string frozenCommitSha,
        CancellationToken cancellationToken = default)
    {
        ImmutableArray<GitBlobEntry> frozen = await ReadEntriesAsync(
                repositoryRoot,
                ["ls-tree", "-r", "-z", "--full-tree", frozenCommitSha, "--", "src"],
                GitListingKind.Tree,
                cancellationToken)
            .ConfigureAwait(false);
        ImmutableArray<GitBlobEntry> current = await ReadEntriesAsync(
                repositoryRoot,
                ["ls-files", "--stage", "-z", "--", "src"],
                GitListingKind.Index,
                cancellationToken)
            .ConfigureAwait(false);
        if (frozen.IsEmpty || current.IsEmpty)
        {
            throw new InvalidDataException(
                "The frozen commit and current index must contain tracked src/ files.");
        }

        string frozenHash = await ComputeHashAsync(
                repositoryRoot,
                frozen,
                cancellationToken)
            .ConfigureAwait(false);
        string currentHash = frozen.SequenceEqual(current)
            ? frozenHash
            : await ComputeHashAsync(repositoryRoot, current, cancellationToken)
                .ConfigureAwait(false);
        return new SourceTreeHashResult(frozenHash, currentHash);
    }

    private async ValueTask<ImmutableArray<GitBlobEntry>> ReadEntriesAsync(
        string repositoryRoot,
        ImmutableArray<string> arguments,
        GitListingKind listingKind,
        CancellationToken cancellationToken)
    {
        var invocation = new ProcessInvocation(
            "git",
            ["-C", repositoryRoot, .. arguments],
            repositoryRoot,
            limits.ProcessTimeout,
            limits.MaximumProcessOutputCharacters);
        BinaryProcessExecutionResult result = await processRunner.RunBinaryAsync(
                invocation,
                maximumOutputBytes: 8 * 1024 * 1024,
                cancellationToken)
            .ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new InvalidDataException(
                "Git could not enumerate tracked product-source blobs.");
        }

        string listing = new UTF8Encoding(false, true).GetString(
            result.StandardOutput);
        var entries = ImmutableArray.CreateBuilder<GitBlobEntry>();
        foreach (string record in listing.Split(
                     '\0',
                     StringSplitOptions.RemoveEmptyEntries))
        {
            entries.Add(ParseEntry(record, listingKind));
        }

        GitBlobEntry[] ordered = entries
            .OrderBy(item => item.Path, StringComparer.Ordinal)
            .ToArray();
        for (var index = 1; index < ordered.Length; index++)
        {
            if (string.Equals(
                ordered[index - 1].Path,
                ordered[index].Path,
                StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Git source listing repeats '{ordered[index].Path}'.");
            }
        }

        return ordered.ToImmutableArray();
    }

    private static GitBlobEntry ParseEntry(
        string record,
        GitListingKind listingKind)
    {
        int tab = record.IndexOf('\t', StringComparison.Ordinal);
        if (tab <= 0 || tab == record.Length - 1)
        {
            throw new InvalidDataException("Git returned an invalid source-tree record.");
        }

        string[] header = record[..tab].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string path = record[(tab + 1)..];
        StablePath.RequireRepositoryRelative(path, "Git source path");
        if (!path.StartsWith("src/", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Git returned a tracked source path outside src/.");
        }

        string objectId;
        if (listingKind == GitListingKind.Tree)
        {
            if (header.Length != 3 || header[1] != "blob")
            {
                throw new InvalidDataException(
                    "The frozen source tree contains a non-blob entry.");
            }

            objectId = header[2];
        }
        else
        {
            if (header.Length != 3 || header[2] != "0")
            {
                throw new InvalidDataException(
                    "The current source index contains an unmerged entry.");
            }

            objectId = header[1];
        }

        if (objectId.Length is not (40 or 64)
            || objectId.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException("Git returned an invalid blob object id.");
        }

        return new GitBlobEntry(path, objectId.ToLowerInvariant());
    }

    private async ValueTask<string> ComputeHashAsync(
        string repositoryRoot,
        ImmutableArray<GitBlobEntry> entries,
        CancellationToken cancellationToken)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(AlgorithmPrefix);
        foreach (GitBlobEntry entry in entries)
        {
            byte[] pathBytes = Encoding.UTF8.GetBytes(entry.Path);
            AppendUInt32(hash, checked((uint)pathBytes.Length));
            hash.AppendData(pathBytes);
            byte[] blob = await ReadBlobAsync(
                    repositoryRoot,
                    entry.ObjectId,
                    cancellationToken)
                .ConfigureAwait(false);
            AppendUInt64(hash, checked((ulong)blob.LongLength));
            hash.AppendData(blob);
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private async ValueTask<byte[]> ReadBlobAsync(
        string repositoryRoot,
        string objectId,
        CancellationToken cancellationToken)
    {
        var invocation = new ProcessInvocation(
            "git",
            ["-C", repositoryRoot, "cat-file", "blob", objectId],
            repositoryRoot,
            limits.ProcessTimeout,
            limits.MaximumProcessOutputCharacters);
        BinaryProcessExecutionResult result = await processRunner.RunBinaryAsync(
                invocation,
                checked((int)Math.Min(limits.MaximumSarifBytes, int.MaxValue)),
                cancellationToken)
            .ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new InvalidDataException(
                "Git could not read a tracked product-source blob.");
        }

        return result.StandardOutput;
    }

    private static void AppendUInt32(IncrementalHash hash, uint value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static void AppendUInt64(IncrementalHash hash, ulong value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private sealed record GitBlobEntry(string Path, string ObjectId);

    private enum GitListingKind
    {
        Tree,
        Index,
    }
}

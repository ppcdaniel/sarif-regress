using System.Collections.Immutable;

namespace SarifRegress.Sarif.Repository;

/// <summary>
/// Binds canonical repository-relative paths to independently trusted raw-byte digests.
/// </summary>
public sealed class RepositorySnapshotManifest
{
    internal RepositorySnapshotManifest(
        ImmutableDictionary<string, string> expectedSha256ByPath)
    {
        ExpectedSha256ByPath = expectedSha256ByPath;
    }

    /// <summary>
    /// Gets the number of source files admitted by this snapshot.
    /// </summary>
    public int FileCount => ExpectedSha256ByPath.Count;

    internal ImmutableDictionary<string, string> ExpectedSha256ByPath { get; }

    internal bool TryGetExpectedSha256(
        string canonicalRepositoryRelativePath,
        out string expectedSha256) =>
        ExpectedSha256ByPath.TryGetValue(
            canonicalRepositoryRelativePath,
            out expectedSha256!);
}

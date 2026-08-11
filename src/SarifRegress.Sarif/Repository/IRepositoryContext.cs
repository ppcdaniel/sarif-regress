using System.Collections.Immutable;
using SarifRegress.Core.Diagnostics;
using SarifRegress.Core.Findings;

namespace SarifRegress.Sarif.Repository;

/// <summary>
/// Represents the result of one bounded, read-only repository source lookup.
/// </summary>
public sealed record RepositoryContextResult(
    bool Exists,
    string? Snippet,
    ContextEvidence? Evidence,
    ImmutableArray<Diagnostic> Diagnostics);

/// <summary>
/// Supplies bounded, read-only source evidence without exposing filesystem access to the core.
/// </summary>
/// <remarks>The creator owns and disposes each repository context.</remarks>
public interface IRepositoryContext : IDisposable
{
    /// <summary>
    /// Reads a bounded source window around a one-based region.
    /// </summary>
    /// <param name="repositoryRelativePath">A canonical repository-relative path.</param>
    /// <param name="region">The finding region.</param>
    /// <param name="lineRadius">The number of surrounding lines to include.</param>
    /// <param name="sourceReference">The source pointer used by diagnostics.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <param name="includeTokenWindow">
    /// Whether to derive a bounded, whitespace-insensitive token window.
    /// </param>
    /// <returns>Stable source evidence or deterministic diagnostics.</returns>
    ValueTask<RepositoryContextResult> ReadAsync(
        string repositoryRelativePath,
        Region? region,
        int lineRadius,
        SourceReference? sourceReference = null,
        CancellationToken cancellationToken = default,
        bool includeTokenWindow = false);
}

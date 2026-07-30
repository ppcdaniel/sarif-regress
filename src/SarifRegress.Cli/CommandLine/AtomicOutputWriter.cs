using System.Collections.Immutable;

namespace SarifRegress.Cli.CommandLine;

/// <summary>
/// Represents one fully materialized output file.
/// </summary>
internal sealed record OutputArtifact(string Path, byte[] Bytes);

/// <summary>
/// Stages complete sibling files before replacing any destination.
/// </summary>
internal static class AtomicOutputWriter
{
    /// <summary>
    /// Writes a set of outputs transactionally within each destination filesystem.
    /// </summary>
    public static async Task WriteAsync(
        ImmutableArray<OutputArtifact> artifacts,
        CancellationToken cancellationToken)
    {
        if (artifacts.IsDefaultOrEmpty)
        {
            return;
        }

        ValidateDistinctPaths(artifacts);
        var staged = new List<StagedArtifact>(artifacts.Length);
        var committed = false;
        try
        {
            foreach (var artifact in artifacts.OrderBy(
                         item => item.Path,
                         StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var directory = System.IO.Path.GetDirectoryName(artifact.Path)
                    ?? throw new IOException(
                        "The output path has no containing directory.");
                Directory.CreateDirectory(directory);
                var temporaryPath = CreateSiblingPath(
                    directory,
                    System.IO.Path.GetFileName(artifact.Path),
                    ".tmp");
                staged.Add(
                    new StagedArtifact(
                        artifact.Path,
                        temporaryPath,
                        BackupPath: null,
                        DestinationReplaced: false));
                await File.WriteAllBytesAsync(
                        temporaryPath,
                        artifact.Bytes,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            ValidateDistinctPaths(artifacts);
            Commit(staged);
            committed = true;
        }
        catch
        {
            RollBack(staged);
            throw;
        }
        finally
        {
            CleanUp(staged, deleteBackups: committed);
        }
    }

    private static void ValidateDistinctPaths(
        ImmutableArray<OutputArtifact> artifacts)
    {
        var identities = artifacts
            .Select(artifact =>
                PathIdentityResolver.ResolveOutputIdentity(artifact.Path))
            .ToArray();
        if (identities.Distinct(PathIdentityResolver.Comparer).Count() !=
            identities.Length)
        {
            throw new IOException(
                "Two output paths resolve to the same destination.");
        }
    }

    private static void Commit(IList<StagedArtifact> staged)
    {
        for (var index = 0; index < staged.Count; index++)
        {
            var artifact = staged[index];
            string? backupPath = null;
            if (File.Exists(artifact.DestinationPath))
            {
                var directory = System.IO.Path.GetDirectoryName(
                    artifact.DestinationPath)
                    ?? throw new IOException(
                        "The output path has no containing directory.");
                backupPath = CreateSiblingPath(
                    directory,
                    System.IO.Path.GetFileName(artifact.DestinationPath),
                    ".bak");
                File.Move(artifact.DestinationPath, backupPath);
                artifact = artifact with { BackupPath = backupPath };
                staged[index] = artifact;
            }

            File.Move(artifact.TemporaryPath, artifact.DestinationPath);
            staged[index] = artifact with { DestinationReplaced = true };
        }
    }

    private static void RollBack(IList<StagedArtifact> staged)
    {
        for (var index = staged.Count - 1; index >= 0; index--)
        {
            var artifact = staged[index];
            try
            {
                if (artifact.DestinationReplaced &&
                    File.Exists(artifact.DestinationPath))
                {
                    File.Delete(artifact.DestinationPath);
                }

                if (artifact.BackupPath is not null &&
                    File.Exists(artifact.BackupPath) &&
                    !File.Exists(artifact.DestinationPath))
                {
                    File.Move(artifact.BackupPath, artifact.DestinationPath);
                }
            }
            catch (IOException)
            {
                // Preserve the original write failure and continue best-effort rollback.
            }
            catch (UnauthorizedAccessException)
            {
                // Preserve the original write failure and continue best-effort rollback.
            }
        }
    }

    private static void CleanUp(
        IEnumerable<StagedArtifact> staged,
        bool deleteBackups)
    {
        foreach (var artifact in staged)
        {
            TryDelete(artifact.TemporaryPath);
            if (deleteBackups && artifact.BackupPath is not null)
            {
                TryDelete(artifact.BackupPath);
            }
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Cleanup cannot change the result after commit or rollback.
        }
        catch (UnauthorizedAccessException)
        {
            // Cleanup cannot change the result after commit or rollback.
        }
    }

    private static string CreateSiblingPath(
        string directory,
        string fileName,
        string suffix)
    {
        string path;
        do
        {
            path = System.IO.Path.Combine(
                directory,
                $".{fileName}.{System.IO.Path.GetRandomFileName()}{suffix}");
        }
        while (File.Exists(path));

        return path;
    }

    private sealed record StagedArtifact(
        string DestinationPath,
        string TemporaryPath,
        string? BackupPath,
        bool DestinationReplaced);
}

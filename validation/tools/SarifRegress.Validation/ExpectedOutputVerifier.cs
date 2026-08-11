namespace SarifRegress.Validation;

/// <summary>
/// Performs exact byte comparisons against the committed evaluation snapshot.
/// </summary>
public static class ExpectedOutputVerifier
{
    /// <summary>Fails at the first ordinal filename whose bytes differ or are absent.</summary>
    public static void Verify(
        string expectedRoot,
        IReadOnlyDictionary<string, byte[]> generatedFiles)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedRoot);
        ArgumentNullException.ThrowIfNull(generatedFiles);
        if (!Directory.Exists(expectedRoot))
        {
            throw new DirectoryNotFoundException(
                "The expected-output root does not exist.");
        }

        string[] actualNames = Directory.EnumerateFiles(
                expectedRoot,
                "*",
                SearchOption.TopDirectoryOnly)
            .Select(path => Path.GetFileName(path)
                ?? throw new InvalidDataException(
                    "An expected-output path has no file name."))
            .Order(StringComparer.Ordinal)
            .ToArray();
        string[] requiredNames = generatedFiles.Keys
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!actualNames.SequenceEqual(requiredNames, StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The expected-output root does not contain the exact normalized output set.");
        }

        foreach ((string name, byte[] generated) in generatedFiles.OrderBy(
                     item => item.Key,
                     StringComparer.Ordinal))
        {
            string expectedPath = Path.Combine(expectedRoot, name);
            byte[] expected = BoundedJsonFile.ReadBytes(
                expectedPath,
                ValidationLimits.Default.MaximumSarifBytes,
                expectedRoot);
            if (!generated.AsSpan().SequenceEqual(expected))
            {
                throw new InvalidDataException(
                    $"Generated output '{name}' differs byte-for-byte from the committed snapshot.");
            }
        }
    }
}

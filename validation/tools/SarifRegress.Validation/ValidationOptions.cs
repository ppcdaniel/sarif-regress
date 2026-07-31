using System.Collections.Immutable;

namespace SarifRegress.Validation;

/// <summary>
/// Defines the only supported validation operation.
/// </summary>
public enum ValidationCommand
{
    /// <summary>Validate structure and execute both matchers.</summary>
    Evaluate,

    /// <summary>Validate manifest, provenance, labels, and schemas without executing tools.</summary>
    ValidateStructure,
}

/// <summary>
/// Carries one fully validated command-line request.
/// </summary>
public sealed record ValidationOptions(
    ValidationCommand Command,
    string RepositoryRoot,
    string OutputRoot,
    string? ExpectedRoot,
    string? MultitoolPath,
    string? MultitoolVersion,
    bool CompareExpected,
    string? CrossPlatformAttestationPath);

/// <summary>
/// Parses a deliberately small, strict command line without ambient defaults.
/// </summary>
public static class ValidationOptionsParser
{
    private const string EvaluateCommandName = "evaluate";
    private const string ValidateStructureCommandName = "validate-structure";

    private static readonly ImmutableHashSet<string> KnownOptions =
        ImmutableHashSet.Create(
            StringComparer.Ordinal,
            "--repository-root",
            "--output-root",
            "--expected-root",
            "--multitool-path",
            "--multitool-version",
            "--compare-expected",
            "--cross-platform-attestation");

    /// <summary>Gets stable command help used by both the CLI and tests.</summary>
    public static string HelpText =>
        "Usage:\n"
        + "  SarifRegress.Validation evaluate --repository-root PATH --output-root PATH "
        + "--multitool-path PATH --multitool-version VERSION "
        + "--compare-expected true|false [--expected-root PATH] "
        + "[--cross-platform-attestation PATH]\n"
        + "  SarifRegress.Validation validate-structure --repository-root PATH "
        + "--output-root PATH\n\n"
        + "evaluate reads the committed frozen evaluation metadata and writes "
        + "sarif-regress-holdout.json, sarif-multitool-baseline.json, "
        + "comparison-summary.json, and "
        + "checksums.sha256. Raw Multitool SARIF is written only below output-root/raw.\n"
        + "When --compare-expected is true, --expected-root is required and all four "
        + "project-owned deterministic outputs are compared byte-for-byte. The optional "
        + "cross-platform attestation must be the fixed committed validation input; when "
        + "omitted, reports are written with a blocked unattested release condition.";

    /// <summary>
    /// Parses and validates one invocation. Duplicate and unknown options are rejected.
    /// </summary>
    public static ValidationOptions Parse(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count == 0 || arguments[0] is "--help" or "-h")
        {
            throw new ValidationUsageException("A validation command is required.");
        }

        ValidationCommand command = ParseCommand(arguments[0]);
        Dictionary<string, string> values = ParseOptionPairs(arguments);
        string repositoryRoot = RequiredPath(values, "--repository-root");
        string outputRoot = RequiredPath(values, "--output-root");
        string? expectedRoot = OptionalPath(values, "--expected-root");

        ValidateOutputRoot(repositoryRoot, outputRoot);

        if (expectedRoot is not null && PathsOverlap(outputRoot, expectedRoot))
        {
            throw new ValidationUsageException(
                "The generated output root must not overlap the committed expected-output root.");
        }

        if (command == ValidationCommand.ValidateStructure)
        {
            RejectOptions(
                values,
                "--expected-root",
                "--multitool-path",
                "--multitool-version",
                "--compare-expected",
                "--cross-platform-attestation");
            return new ValidationOptions(
                command,
                repositoryRoot,
                outputRoot,
                null,
                null,
                null,
                CompareExpected: false,
                CrossPlatformAttestationPath: null);
        }

        string multitoolPath = RequiredValue(values, "--multitool-path");
        string multitoolVersion = RequiredValue(values, "--multitool-version");
        bool compareExpected = RequiredBoolean(values, "--compare-expected");
        string? crossPlatformAttestation = OptionalPath(
            values,
            "--cross-platform-attestation");
        ValidateVersion(multitoolVersion);
        if (crossPlatformAttestation is not null)
        {
            ValidateAttestationPath(repositoryRoot, crossPlatformAttestation);
        }
        if (compareExpected && expectedRoot is null)
        {
            throw new ValidationUsageException(
                "--expected-root is required when --compare-expected is true.");
        }

        return new ValidationOptions(
            command,
            repositoryRoot,
            outputRoot,
            expectedRoot,
            multitoolPath,
            multitoolVersion,
            compareExpected,
            crossPlatformAttestation);
    }

    private static ValidationCommand ParseCommand(string value) => value switch
    {
        EvaluateCommandName => ValidationCommand.Evaluate,
        ValidateStructureCommandName => ValidationCommand.ValidateStructure,
        _ => throw new ValidationUsageException(
            $"Unknown validation command '{value}'."),
    };

    private static Dictionary<string, string> ParseOptionPairs(
        IReadOnlyList<string> arguments)
    {
        if ((arguments.Count - 1) % 2 != 0)
        {
            throw new ValidationUsageException(
                "Every validation option requires exactly one value.");
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < arguments.Count; index += 2)
        {
            string option = arguments[index];
            if (!KnownOptions.Contains(option))
            {
                throw new ValidationUsageException(
                    $"Unknown validation option '{option}'.");
            }

            if (!values.TryAdd(option, arguments[index + 1]))
            {
                throw new ValidationUsageException(
                    $"Validation option '{option}' was supplied more than once.");
            }
        }

        return values;
    }

    private static string RequiredPath(
        IReadOnlyDictionary<string, string> values,
        string option) => Path.GetFullPath(RequiredValue(values, option));

    private static string? OptionalPath(
        IReadOnlyDictionary<string, string> values,
        string option) => values.TryGetValue(option, out string? value)
            ? Path.GetFullPath(RequireNonBlank(option, value))
            : null;

    private static string RequiredValue(
        IReadOnlyDictionary<string, string> values,
        string option)
    {
        if (!values.TryGetValue(option, out string? value))
        {
            throw new ValidationUsageException(
                $"Required validation option '{option}' is missing.");
        }

        return RequireNonBlank(option, value);
    }

    private static string RequireNonBlank(string option, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ValidationUsageException(
                $"Validation option '{option}' cannot be empty.");
        }

        return value;
    }

    private static bool RequiredBoolean(
        IReadOnlyDictionary<string, string> values,
        string option)
    {
        string value = RequiredValue(values, option);
        return value switch
        {
            "true" => true,
            "false" => false,
            _ => throw new ValidationUsageException(
                $"Validation option '{option}' must be exactly 'true' or 'false'."),
        };
    }

    private static void ValidateVersion(string version)
    {
        if (!string.Equals(
                version,
                MultitoolRunner.ExactVersion,
                StringComparison.Ordinal))
        {
            throw new ValidationUsageException(
                "--multitool-version must be the repository-pinned exact version "
                + $"{MultitoolRunner.ExactVersion}.");
        }
    }

    private static void ValidateAttestationPath(
        string repositoryRoot,
        string suppliedPath)
    {
        string expectedPath = CrossPlatformAttestationReader.GetPath(repositoryRoot);
        if (!string.Equals(
            expectedPath,
            suppliedPath,
            OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal))
        {
            throw new ValidationUsageException(
                "--cross-platform-attestation must identify the fixed committed "
                + $"'{CrossPlatformAttestationReader.RelativePath}' file.");
        }
    }

    private static void RejectOptions(
        IReadOnlyDictionary<string, string> values,
        params string[] rejected)
    {
        string? present = rejected.FirstOrDefault(values.ContainsKey);
        if (present is not null)
        {
            throw new ValidationUsageException(
                $"Validation option '{present}' is not valid for validate-structure.");
        }
    }

    private static bool PathsOverlap(string left, string right)
    {
        string normalizedLeft = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(left));
        string normalizedRight = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(right));
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        return string.Equals(normalizedLeft, normalizedRight, comparison)
            || IsChild(normalizedLeft, normalizedRight, comparison)
            || IsChild(normalizedRight, normalizedLeft, comparison);
    }

    private static bool IsChild(
        string parent,
        string candidate,
        StringComparison comparison) => candidate.StartsWith(
            parent + Path.DirectorySeparatorChar,
            comparison);

    private static void ValidateOutputRoot(
        string repositoryRoot,
        string outputRoot)
    {
        string repository = Path.TrimEndingDirectorySeparator(repositoryRoot);
        string output = Path.TrimEndingDirectorySeparator(outputRoot);
        string? filesystemRoot = Path.GetPathRoot(outputRoot);
        if (filesystemRoot is not null
            && string.Equals(
                Path.TrimEndingDirectorySeparator(filesystemRoot),
                output,
                OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal))
        {
            throw new ValidationUsageException(
                "A filesystem root cannot be used as the validation output root.");
        }

        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (string.Equals(repository, output, comparison))
        {
            throw new ValidationUsageException(
                "The repository root itself cannot be used as the validation output root.");
        }

        if (!IsChild(repository, output, comparison))
        {
            return;
        }

        string relative = Path.GetRelativePath(repository, output)
            .Replace(Path.DirectorySeparatorChar, '/');
        if (!relative.Equals("artifacts", StringComparison.OrdinalIgnoreCase)
            && !relative.StartsWith("artifacts/", StringComparison.OrdinalIgnoreCase))
        {
            throw new ValidationUsageException(
                "An in-repository validation output root must be below artifacts/.");
        }
    }
}

/// <summary>Represents a deterministic command-line contract violation.</summary>
public sealed class ValidationUsageException(string message) : Exception(message);

/// <summary>Defines stable process exit codes for the validation-only executable.</summary>
public static class ValidationExitCodes
{
    /// <summary>The evaluation completed, including honest matcher defects.</summary>
    public const int Success = 0;

    /// <summary>The command line did not satisfy the strict invocation contract.</summary>
    public const int InvalidInvocation = 1;

    /// <summary>Structure, provenance, schema, tool execution, or bytes were invalid.</summary>
    public const int ValidationFailure = 2;
}

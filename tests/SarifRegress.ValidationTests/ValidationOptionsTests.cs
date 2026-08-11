using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class ValidationOptionsTests
{
    [Fact]
    public void Evaluate_rejects_a_well_formed_but_unpinned_multitool_version()
    {
        string outputRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            var exception = Assert.Throws<ValidationUsageException>(() =>
                ValidationOptionsParser.Parse(CreateArguments(
                    outputRoot,
                    "5.4.0")));

            Assert.Contains(
                "repository-pinned exact version 5.5.0",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(outputRoot, recursive: true);
        }
    }

    [Fact]
    public void Evaluate_accepts_only_the_repository_pinned_multitool_version()
    {
        string outputRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            ValidationOptions options = ValidationOptionsParser.Parse(
                CreateArguments(outputRoot, MultitoolRunner.ExactVersion));

            Assert.Equal("5.5.0", options.MultitoolVersion);
            Assert.Equal(ValidationCommand.Evaluate, options.Command);
            Assert.Null(options.CrossPlatformAttestationPath);
        }
        finally
        {
            Directory.Delete(outputRoot, recursive: true);
        }
    }

    [Fact]
    public void Evaluate_accepts_only_the_fixed_committed_attestation_path()
    {
        string outputRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            string repositoryRoot = ValidationTestRepository.FindRoot();
            string expectedPath = CrossPlatformAttestationReader.GetPath(repositoryRoot);
            ValidationOptions options = ValidationOptionsParser.Parse(
            [
                .. CreateArguments(outputRoot, MultitoolRunner.ExactVersion),
                "--cross-platform-attestation",
                expectedPath,
            ]);

            Assert.Equal(expectedPath, options.CrossPlatformAttestationPath);

            var exception = Assert.Throws<ValidationUsageException>(() =>
                ValidationOptionsParser.Parse(
                [
                    .. CreateArguments(outputRoot, MultitoolRunner.ExactVersion),
                    "--cross-platform-attestation",
                    Path.Combine(repositoryRoot, "attestation.json"),
                ]));
            Assert.Contains(
                CrossPlatformAttestationReader.RelativePath,
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(outputRoot, recursive: true);
        }
    }

    [Fact]
    public void Evaluate_rejects_the_removed_free_byte_identity_switch()
    {
        string outputRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            var exception = Assert.Throws<ValidationUsageException>(() =>
                ValidationOptionsParser.Parse(
                [
                    .. CreateArguments(outputRoot, MultitoolRunner.ExactVersion),
                    "--cross-platform-byte-identity",
                    "true",
                ]));

            Assert.Contains(
                "Unknown validation option",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(outputRoot, recursive: true);
        }
    }

    private static string[] CreateArguments(
        string outputRoot,
        string multitoolVersion) =>
    [
        "evaluate",
        "--repository-root",
        ValidationTestRepository.FindRoot(),
        "--output-root",
        outputRoot,
        "--multitool-path",
        "sarif",
        "--multitool-version",
        multitoolVersion,
        "--compare-expected",
        "false",
    ];
}

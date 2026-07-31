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
        "--cross-platform-byte-identity",
        "false",
    ];
}

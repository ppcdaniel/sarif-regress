using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class ValidationApplicationSafetyTests
{
    [Fact]
    public async Task Evaluator_rejects_a_nonempty_output_root_before_reading_inputs()
    {
        string outputRoot = ValidationTestRepository.CreateTemporaryDirectory();
        string markerPath = Path.Combine(outputRoot, "preexisting.txt");
        File.WriteAllText(markerPath, "must not be overwritten\n");
        try
        {
            InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(
                async () => await new ValidationApplication().RunAsync(
                    CreateOptions(outputRoot),
                    TestContext.Current.CancellationToken));

            Assert.Contains(
                "must be empty at startup",
                exception.Message,
                StringComparison.Ordinal);
            Assert.Equal("must not be overwritten\n", File.ReadAllText(markerPath));
        }
        finally
        {
            Directory.Delete(outputRoot, recursive: true);
        }
    }

    [Fact]
    public async Task Evaluator_rejects_a_symlink_or_reparse_point_output_root()
    {
        string container = ValidationTestRepository.CreateTemporaryDirectory();
        string target = Path.Combine(container, "target");
        string link = Path.Combine(container, "output-link");
        Directory.CreateDirectory(target);
        try
        {
            try
            {
                _ = Directory.CreateSymbolicLink(link, target);
            }
            catch (Exception exception) when (exception is
                NotSupportedException or
                UnauthorizedAccessException or
                IOException or
                System.Security.SecurityException)
            {
                return;
            }

            Assert.True(
                (File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0,
                "The platform created a directory alias without reporting it as a reparse point.");
            InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(
                async () => await new ValidationApplication().RunAsync(
                    CreateOptions(link),
                    TestContext.Current.CancellationToken));

            Assert.Contains(
                "regular non-reparse directory",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(link))
            {
                Directory.Delete(link);
            }

            Directory.Delete(container, recursive: true);
        }
    }

    private static ValidationOptions CreateOptions(string outputRoot) => new(
        ValidationCommand.ValidateStructure,
        ValidationTestRepository.FindRoot(),
        outputRoot,
        ExpectedRoot: null,
        MultitoolPath: null,
        MultitoolVersion: null,
        CompareExpected: false,
        CrossPlatformByteIdentity: false);
}

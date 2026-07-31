using System.Security.Cryptography;
using System.Text;

namespace SarifRegress.ValidationTests;

internal static class ValidationTestRepository
{
    public static string FindRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(
                directory.FullName,
                "validation",
                "schemas",
                "holdout-manifest.schema.json");
            if (File.Exists(candidate))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate the validation repository from the test output directory.");
    }

    public static string CreateTemporaryDirectory()
    {
        string path = Path.Combine(
            Path.GetTempPath(),
            $"sarif-regress-validation-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    public static string CopyStructuralInputsToTemporaryRepository()
    {
        string sourceRoot = FindRoot();
        string destinationRoot = CreateTemporaryDirectory();
        CopyDirectory(
            Path.Combine(sourceRoot, "validation", "holdout"),
            Path.Combine(destinationRoot, "validation", "holdout"));
        CopyDirectory(
            Path.Combine(sourceRoot, "validation", "schemas"),
            Path.Combine(destinationRoot, "validation", "schemas"));
        CopyDirectory(
            Path.Combine(sourceRoot, "validation", "tools", "capture"),
            Path.Combine(destinationRoot, "validation", "tools", "capture"));
        CopyDirectory(
            Path.Combine(sourceRoot, "corpus", "schema"),
            Path.Combine(destinationRoot, "corpus", "schema"));

        string sourceCorpusCases = Path.Combine(sourceRoot, "corpus", "cases");
        string destinationCorpusCases = Path.Combine(
            destinationRoot,
            "corpus",
            "cases");
        Directory.CreateDirectory(destinationCorpusCases);
        foreach (string directory in Directory.EnumerateDirectories(sourceCorpusCases))
        {
            Directory.CreateDirectory(
                Path.Combine(destinationCorpusCases, Path.GetFileName(directory)));
        }

        return destinationRoot;
    }

    public static IReadOnlyDictionary<string, string> HashTree(string directory)
    {
        return Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .OrderBy(
                path => Path.GetRelativePath(directory, path)
                    .Replace(Path.DirectorySeparatorChar, '/'),
                StringComparer.Ordinal)
            .ToDictionary(
                path => Path.GetRelativePath(directory, path)
                    .Replace(Path.DirectorySeparatorChar, '/'),
                path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))
                    .ToLowerInvariant(),
                StringComparer.Ordinal);
    }

    public static byte[] Utf8(string value) => new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true).GetBytes(value);

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string file in Directory.EnumerateFiles(source))
        {
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        }

        foreach (string directory in Directory.EnumerateDirectories(source))
        {
            CopyDirectory(
                directory,
                Path.Combine(destination, Path.GetFileName(directory)));
        }
    }
}

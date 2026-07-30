namespace SarifRegress.UnitTests;

internal static class RepositoryLayout
{
    public static string Root { get; } = FindRoot();

    private static string FindRoot()
    {
        for (
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            directory is not null;
            directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "SarifRegress.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException(
            "Could not locate the repository root containing SarifRegress.slnx.");
    }
}

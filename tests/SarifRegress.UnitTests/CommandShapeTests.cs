using System.Xml.Linq;
using SarifRegress.Cli.CommandLine;

namespace SarifRegress.UnitTests;

public sealed class CommandShapeTests
{
    private static readonly string[] ExpectedOptionNames =
    [
        "--baseline",
        "--candidate",
        "--config",
        "--html-out",
        "--json-out",
        "--repo",
        "--sarif-out",
    ];

    [Fact]
    public void Command_tree_exposes_compare_and_all_supported_options()
    {
        var rootCommand = CliCommandFactory.Create();
        Assert.Equal(
            ["bench", "canonicalise", "compare", "corpus", "validate"],
            rootCommand.Subcommands
                .Select(command => command.Name)
                .Order(StringComparer.Ordinal));

        var compareCommand = Assert.Single(
            rootCommand.Subcommands,
            command => command.Name == "compare");

        var actualOptionNames = compareCommand.Options
            .Select(option => option.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(ExpectedOptionNames, actualOptionNames);
        Assert.True(
            compareCommand.Options.Single(option => option.Name == "--baseline").Required);
        Assert.True(
            compareCommand.Options.Single(option => option.Name == "--candidate").Required);
    }

    [Fact]
    public void Cli_project_names_the_root_executable_sarif_regress()
    {
        var cliProjectPath = Path.Combine(
            RepositoryLayout.Root,
            "src",
            "SarifRegress.Cli",
            "SarifRegress.Cli.csproj");
        var projectDocument = XDocument.Load(cliProjectPath);
        var assemblyName = projectDocument
            .Descendants("AssemblyName")
            .Select(element => element.Value)
            .Single();

        Assert.Equal("sarif-regress", assemblyName);
    }
}

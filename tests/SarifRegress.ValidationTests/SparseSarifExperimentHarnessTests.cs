using System.Text;
using System.Text.Json;
using SarifRegress.Core.Security;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class SparseSarifExperimentHarnessTests
{
    [Fact]
    public async Task Resource_limit_evidence_is_stable_and_executable()
    {
        string outputRoot = ValidationTestRepository.CreateTemporaryDirectory();
        try
        {
            ValidationOptions options = ValidationOptionsParser.Parse(
            [
                "resource-limits",
                "--repository-root",
                ValidationTestRepository.FindRoot(),
                "--output-root",
                outputRoot,
            ]);
            Assert.Equal(ValidationCommand.ResourceLimits, options.Command);

            int exitCode = await new ValidationApplication().RunAsync(
                options,
                TestContext.Current.CancellationToken);
            Assert.Equal(ValidationExitCodes.Success, exitCode);
            string outputPath = Path.Combine(
                outputRoot,
                ResourceLimitEvidenceSerializer.OutputFileName);
            byte[] first = File.ReadAllBytes(outputPath);
            byte[] second = ResourceLimitEvidenceSerializer.Serialize();
            Assert.Equal(first, second);
            using var document = JsonDocument.Parse(first);
            JsonElement root = document.RootElement;
            Assert.Equal(
                ResourceLimits.Default.MaximumCandidatePairEvaluationsPerFinding,
                root.GetProperty("maximumCandidatePairsPerFinding").GetInt32());
            Assert.Equal(
                ResourceLimits.Default.MaximumCandidatePairEvaluations,
                root.GetProperty("maximumCandidatePairs").GetInt64());
            Assert.Equal(
                ResourceLimits.Default.MaximumAssignmentSideSize,
                root.GetProperty("maximumAssignmentSideSize").GetInt32());
        }
        finally
        {
            Directory.Delete(outputRoot, recursive: true);
        }
    }

    [Fact]
    public void Sparse_commands_keep_observation_and_label_evaluation_separate()
    {
        string outputRoot = ValidationTestRepository.CreateTemporaryDirectory();
        string observationPath = Path.Combine(outputRoot, "observations.json");
        try
        {
            ValidationOptions run = ValidationOptionsParser.Parse(
            [
                "sparse-run",
                "--repository-root",
                ValidationTestRepository.FindRoot(),
                "--output-root",
                outputRoot,
            ]);
            Assert.Equal(ValidationCommand.SparseRun, run.Command);
            Assert.Null(run.ObservationsPath);

            ValidationOptions evaluate = ValidationOptionsParser.Parse(
            [
                "sparse-evaluate",
                "--repository-root",
                ValidationTestRepository.FindRoot(),
                "--output-root",
                outputRoot,
                "--observations",
                observationPath,
            ]);
            Assert.Equal(ValidationCommand.SparseEvaluate, evaluate.Command);
            Assert.Equal(Path.GetFullPath(observationPath), evaluate.ObservationsPath);

            Assert.Throws<ValidationUsageException>(() =>
                ValidationOptionsParser.Parse(
                [
                    "sparse-run",
                    "--repository-root",
                    ValidationTestRepository.FindRoot(),
                    "--output-root",
                    outputRoot,
                    "--observations",
                    observationPath,
                ]));
            Assert.Throws<ValidationUsageException>(() =>
                ValidationOptionsParser.Parse(
                [
                    "sparse-evaluate",
                    "--repository-root",
                    ValidationTestRepository.FindRoot(),
                    "--output-root",
                    outputRoot,
                ]));
        }
        finally
        {
            Directory.Delete(outputRoot, recursive: true);
        }
    }

    [Fact]
    public void Observation_wire_contract_does_not_expose_matcher_or_label_keys()
    {
        string temporaryRoot = ValidationTestRepository.CreateTemporaryDirectory();
        string path = Path.Combine(temporaryRoot, "observations.json");
        try
        {
            string sha256 = new('0', 64);
            var observations = new SparseExperimentObservations(
                SchemaVersion: "1",
                Kind: SparseSarifExperimentRunner.ObservationsKind,
                sha256,
                sha256,
                Variants: []);
            byte[] first = SparseSarifExperimentSerializer.Serialize(observations);
            byte[] second = SparseSarifExperimentSerializer.Serialize(observations);
            Assert.Equal(first, second);
            string json = Encoding.UTF8.GetString(first);
            Assert.DoesNotContain("findingKey", json, StringComparison.Ordinal);
            Assert.DoesNotContain("resultIndex", json, StringComparison.Ordinal);
            Assert.DoesNotContain("labelsPath", json, StringComparison.Ordinal);

            StableJson.WriteFile(path, first);
            SparseExperimentObservations roundTrip =
                SparseSarifExperimentSerializer.ReadObservations(
                    path,
                    temporaryRoot);
            Assert.Equal(observations, roundTrip);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public async Task Sparse_context_indexing_is_bounded_and_duplicate_context_is_refused()
    {
        string repositoryRoot = ValidationTestRepository.FindRoot();
        string outputRoot = ValidationTestRepository.CreateTemporaryDirectory();
        string observationPath = Path.Combine(
            outputRoot,
            SparseSarifExperimentRunner.OutputFileName);
        try
        {
            SparseExperimentObservations observations =
                await new SparseSarifExperimentRunner().RunAsync(
                    repositoryRoot,
                    outputRoot,
                    TestContext.Current.CancellationToken);
            foreach (SparseVariantObservation variant in observations.Variants)
            {
                foreach (SparseFamilyObservation family in variant.Families)
                {
                    SparseOperationCounts operations = family.OperationCounts;
                    if (string.Equals(
                            variant.Id,
                            SparseExperimentVariants.SarifOnlyControl,
                            StringComparison.Ordinal))
                    {
                        Assert.Equal(0, operations.SourceFindingsIndexed);
                        Assert.Equal(0, operations.SourceAtomsIndexed);
                        Assert.Equal(0, operations.SourceIndexLookups);
                        continue;
                    }

                    Assert.True(operations.SourceFindingsIndexed > 0);
                    Assert.InRange(
                        operations.SourceAtomsIndexed,
                        0,
                        checked(operations.SourceFindingsIndexed * 3));
                    Assert.InRange(
                        operations.SourceIndexLookups,
                        0,
                        checked(operations.SourceAtomsIndexed * 2));
                }
            }

            byte[] observationBytes = SparseSarifExperimentSerializer.Serialize(
                observations);
            string observationJson = Encoding.UTF8.GetString(observationBytes);
            Assert.DoesNotContain("-relationship-", observationJson, StringComparison.Ordinal);
            Assert.DoesNotContain("-ambiguity-", observationJson, StringComparison.Ordinal);
            StableJson.WriteFile(observationPath, observationBytes);

            SparseExperimentGateEvidence evidence =
                new SparseSarifExperimentEvaluator().Evaluate(
                    repositoryRoot,
                    observationPath);
            Assert.All(evidence.Variants, variant =>
                Assert.Equal(0, variant.Ambiguity.IncorrectAutoMatches));
            Assert.All(evidence.Variants, variant =>
            {
                Assert.Equal(
                    variant.Lifecycle.ExpectedNew,
                    checked(
                        variant.Lifecycle.CorrectNew
                        + variant.Lifecycle.IncorrectNew));
                Assert.Equal(
                    variant.Lifecycle.ExpectedResolved,
                    checked(
                        variant.Lifecycle.CorrectResolved
                        + variant.Lifecycle.IncorrectResolved));
                SparseScenarioGateEvidence ambiguity = variant.Scenarios.Single(
                    item => string.Equals(
                        item.ScenarioId,
                        "repeated-context-ambiguity",
                        StringComparison.Ordinal));
                Assert.All(ambiguity.Families, family =>
                    Assert.True(family.AssertionsPassed));
            });
        }
        finally
        {
            Directory.Delete(outputRoot, recursive: true);
        }
    }
}

using System.Security.Cryptography;
using System.Text.Json.Nodes;
using SarifRegress.Validation;

namespace SarifRegress.ValidationTests;

public sealed class CrossPlatformAttestationTests
{
    private const string FrozenCommit =
        "1111111111111111111111111111111111111111";
    private const string WorkflowHead =
        "2222222222222222222222222222222222222222";
    private const string ManifestSha =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string MetadataSha =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string SarifRegressSha =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    private const string MultitoolSha =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    private const string DeltaSha =
        "abababababababababababababababababababababababababababababababab";

    [Fact]
    public void Reader_accepts_exact_hosted_evidence_and_retains_input_bytes()
    {
        string root = CreateRepository();
        try
        {
            string path = WriteAttestation(root, CreateDocument());
            byte[] expectedBytes = File.ReadAllBytes(path);

            ValidatedCrossPlatformAttestation attestation =
                new CrossPlatformAttestationReader().Read(
                    root,
                    path,
                    CreateExpectation());

            Assert.Equal(expectedBytes, attestation.ExactBytes);
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(expectedBytes))
                    .ToLowerInvariant(),
                attestation.Sha256);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("frozen-commit")]
    [InlineData("manifest")]
    [InlineData("metadata")]
    [InlineData("base-sarif-regress")]
    [InlineData("linux-sarif-regress")]
    [InlineData("windows-multitool")]
    [InlineData("linux-delta")]
    [InlineData("run-url")]
    [InlineData("workflow-head")]
    [InlineData("workflow-conclusion")]
    [InlineData("coordinator-job")]
    [InlineData("duplicate-artifact-id")]
    [InlineData("zero-archive-digest")]
    [InlineData("delta-byte-identity")]
    public void Reader_rejects_tampered_identity_or_hosted_evidence(string mutation)
    {
        string root = CreateRepository();
        try
        {
            JsonObject document = CreateDocument();
            Mutate(document, mutation);
            string path = WriteAttestation(root, document);

            Assert.Throws<InvalidDataException>(() =>
                new CrossPlatformAttestationReader().Read(
                    root,
                    path,
                    CreateExpectation()));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("comparisonSummarySha256")]
    [InlineData("checksumManifestSha256")]
    public void Reader_schema_rejects_self_referential_final_output_hashes(
        string propertyName)
    {
        string root = CreateRepository();
        try
        {
            JsonObject document = CreateDocument();
            document[propertyName] = new string('e', 64);
            string path = WriteAttestation(root, document);

            InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
                new CrossPlatformAttestationReader().Read(
                    root,
                    path,
                    CreateExpectation()));
            Assert.Contains(
                "does not satisfy schema",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Reader_schema_rejects_obsolete_v2_to_v3_delta_names()
    {
        string root = CreateRepository();
        try
        {
            JsonObject document = CreateDocument();
            JsonObject byteIdentity = document["byteIdentity"]!.AsObject();
            byteIdentity["v2ToV3Delta"] = byteIdentity["v3ToV31Delta"]!.DeepClone();
            _ = byteIdentity.Remove("v3ToV31Delta");
            RenameDeltaDigest(document["baseReports"]!.AsObject());
            JsonObject artifacts = document["artifacts"]!.AsObject();
            RenameDeltaDigest(
                artifacts["linux"]!.AsObject()["reportDigests"]!.AsObject());
            RenameDeltaDigest(
                artifacts["windows"]!.AsObject()["reportDigests"]!.AsObject());

            string path = WriteAttestation(root, document);

            InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
                new CrossPlatformAttestationReader().Read(
                    root,
                    path,
                    CreateExpectation()));
            Assert.Contains(
                "does not satisfy schema",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        static void RenameDeltaDigest(JsonObject digests)
        {
            digests["v2ToV3DeltaSha256"] =
                digests["v3ToV31DeltaSha256"]!.DeepClone();
            _ = digests.Remove("v3ToV31DeltaSha256");
        }
    }

    [Fact]
    public void Reader_rejects_any_path_other_than_the_fixed_committed_input()
    {
        string root = CreateRepository();
        try
        {
            string path = WriteAttestation(root, CreateDocument());
            string alternate = Path.Combine(root, "attestation.json");
            File.Copy(path, alternate);

            InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
                new CrossPlatformAttestationReader().Read(
                    root,
                    alternate,
                    CreateExpectation()));
            Assert.Contains(
                CrossPlatformAttestationReader.RelativePath,
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static CrossPlatformAttestationExpectation CreateExpectation() => new(
        FrozenCommit,
        ManifestSha,
        MetadataSha,
        SarifRegressSha,
        MultitoolSha,
        DeltaSha);

    private static string CreateRepository()
    {
        string root = ValidationTestRepository.CreateTemporaryDirectory();
        string schemaDirectory = Path.Combine(root, "validation", "schemas");
        Directory.CreateDirectory(schemaDirectory);
        File.Copy(
            Path.Combine(
                ValidationTestRepository.FindRoot(),
                "validation",
                "schemas",
                "cross-platform-attestation.schema.json"),
            Path.Combine(
                schemaDirectory,
                "cross-platform-attestation.schema.json"));
        Directory.CreateDirectory(Path.Combine(root, "validation", "holdout"));
        return root;
    }

    private static string WriteAttestation(string root, JsonObject document)
    {
        string path = CrossPlatformAttestationReader.GetPath(root);
        byte[] bytes = ValidationTestRepository.Utf8(
            document.ToJsonString() + "\n");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static JsonObject CreateDocument() => new()
    {
        ["schemaVersion"] = "3",
        ["repository"] = "ppcdaniel/sarif-regress",
        ["repositoryCommitSha"] = FrozenCommit,
        ["holdoutManifestSha256"] = ManifestSha,
        ["evaluationMetadataSha256"] = MetadataSha,
        ["baseReports"] = ReportDigests(),
        ["githubActions"] = new JsonObject
        {
            ["workflowPath"] = ".github/workflows/holdout-validation.yml",
            ["runId"] = 30654077180L,
            ["runAttempt"] = 1,
            ["runUrl"] = (
                "https://github.com/ppcdaniel/sarif-regress/actions/runs/"
                + "30654077180"),
            ["workflowHeadSha"] = WorkflowHead,
            ["conclusion"] = "success",
            ["coordinatorJobName"] =
                "Compare Linux and Windows normalized bytes",
        },
        ["artifacts"] = new JsonObject
        {
            ["linux"] = Artifact(
                "holdout-linux",
                8802623003L,
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            ["windows"] = Artifact(
                "holdout-windows",
                8802623004L,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        },
        ["byteIdentity"] = new JsonObject
        {
            ["sarifRegressHoldout"] = true,
            ["sarifMultitoolBaseline"] = true,
            ["v3ToV31Delta"] = true,
        },
    };

    private static JsonObject Artifact(
        string name,
        long artifactId,
        string archiveSha256) => new()
        {
            ["name"] = name,
            ["artifactId"] = artifactId,
            ["archiveSha256"] = archiveSha256,
            ["reportDigests"] = ReportDigests(),
        };

    private static JsonObject ReportDigests() => new()
    {
        ["sarifRegressHoldoutSha256"] = SarifRegressSha,
        ["sarifMultitoolBaselineSha256"] = MultitoolSha,
        ["v3ToV31DeltaSha256"] = DeltaSha,
    };

    private static void Mutate(JsonObject document, string mutation)
    {
        JsonObject baseReports = document["baseReports"]!.AsObject();
        JsonObject actions = document["githubActions"]!.AsObject();
        JsonObject artifacts = document["artifacts"]!.AsObject();
        JsonObject linux = artifacts["linux"]!.AsObject();
        JsonObject windows = artifacts["windows"]!.AsObject();
        switch (mutation)
        {
            case "frozen-commit":
                document["repositoryCommitSha"] = WorkflowHead;
                break;
            case "manifest":
                document["holdoutManifestSha256"] = MetadataSha;
                break;
            case "metadata":
                document["evaluationMetadataSha256"] = ManifestSha;
                break;
            case "base-sarif-regress":
                baseReports["sarifRegressHoldoutSha256"] = MultitoolSha;
                break;
            case "linux-sarif-regress":
                linux["reportDigests"]!.AsObject()["sarifRegressHoldoutSha256"] =
                    MultitoolSha;
                break;
            case "windows-multitool":
                windows["reportDigests"]!.AsObject()["sarifMultitoolBaselineSha256"] =
                    SarifRegressSha;
                break;
            case "linux-delta":
                linux["reportDigests"]!.AsObject()["v3ToV31DeltaSha256"] =
                    MultitoolSha;
                break;
            case "run-url":
                actions["runUrl"] =
                    "https://github.com/ppcdaniel/sarif-regress/actions/runs/1";
                break;
            case "workflow-head":
                actions["workflowHeadSha"] = new string('0', 40);
                break;
            case "workflow-conclusion":
                actions["conclusion"] = "failure";
                break;
            case "coordinator-job":
                actions["coordinatorJobName"] = "compare";
                break;
            case "duplicate-artifact-id":
                windows["artifactId"] = linux["artifactId"]!.GetValue<long>();
                break;
            case "zero-archive-digest":
                linux["archiveSha256"] = new string('0', 64);
                break;
            case "delta-byte-identity":
                document["byteIdentity"]!.AsObject()["v3ToV31Delta"] = false;
                break;
            default:
                throw new InvalidOperationException(
                    $"Unknown attestation mutation '{mutation}'.");
        }
    }
}

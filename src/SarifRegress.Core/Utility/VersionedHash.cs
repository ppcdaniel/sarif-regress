using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SarifRegress.Core.Utility;

/// <summary>
/// Computes versioned SHA-256 hashes over unambiguous, length-prefixed UTF-8 fields.
/// </summary>
public static class VersionedHash
{
    private static readonly UTF8Encoding StableUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <summary>
    /// Computes a lowercase SHA-256 digest over a version and ordered field sequence.
    /// </summary>
    /// <param name="algorithmVersion">The versioned algorithm identifier.</param>
    /// <param name="fields">The ordered fields. A null field is distinct from an empty field.</param>
    /// <returns>The lowercase hexadecimal digest.</returns>
    public static string Compute(string algorithmVersion, params string?[] fields)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmVersion);
        ArgumentNullException.ThrowIfNull(fields);

        using var incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendField(incrementalHash, algorithmVersion);

        foreach (var field in fields)
        {
            AppendField(incrementalHash, field);
        }

        return Convert.ToHexString(incrementalHash.GetHashAndReset()).ToLowerInvariant();
    }

    private static void AppendField(IncrementalHash hash, string? value)
    {
        Span<byte> lengthBytes = stackalloc byte[sizeof(int)];
        if (value is null)
        {
            BinaryPrimitives.WriteInt32BigEndian(lengthBytes, -1);
            hash.AppendData(lengthBytes);
            return;
        }

        var byteCount = StableUtf8.GetByteCount(value);
        BinaryPrimitives.WriteInt32BigEndian(lengthBytes, byteCount);
        hash.AppendData(lengthBytes);

        if (byteCount == 0)
        {
            return;
        }

        var valueBytes = StableUtf8.GetBytes(value);
        hash.AppendData(valueBytes);
    }
}

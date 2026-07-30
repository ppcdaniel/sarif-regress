namespace SarifRegress.Sarif.Ingestion;

/// <summary>
/// Indicates that an untrusted stream exceeded its configured byte budget.
/// </summary>
internal sealed class InputLimitExceededException : IOException
{
    public InputLimitExceededException(long maximumBytes)
        : base($"The input exceeds the configured limit of {maximumBytes} bytes.")
    {
        MaximumBytes = maximumBytes;
    }

    public long MaximumBytes { get; }
}

/// <summary>
/// Counts bytes returned by an underlying stream and fails before exposing bytes beyond the limit.
/// </summary>
internal sealed class BoundedReadStream : Stream
{
    private readonly Stream inner;
    private readonly long maximumBytes;
    private long bytesRead;

    public BoundedReadStream(Stream inner, long maximumBytes)
    {
        ArgumentNullException.ThrowIfNull(inner);
        if (!inner.CanRead)
        {
            throw new ArgumentException("The input stream must be readable.", nameof(inner));
        }

        if (maximumBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumBytes),
                maximumBytes,
                "The byte limit must be positive.");
        }

        this.inner = inner;
        this.maximumBytes = maximumBytes;
    }

    public long BytesRead => bytesRead;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => bytesRead;
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateReadArguments(buffer, offset, count);
        var allowedCount = GetAllowedReadCount(count);
        var read = inner.Read(buffer, offset, allowedCount);
        AccountForRead(read);
        return read;
    }

    public override int Read(Span<byte> buffer)
    {
        var allowedCount = GetAllowedReadCount(buffer.Length);
        var read = inner.Read(buffer[..allowedCount]);
        AccountForRead(read);
        return read;
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        var allowedCount = GetAllowedReadCount(buffer.Length);
        var read = await inner
            .ReadAsync(buffer[..allowedCount], cancellationToken)
            .ConfigureAwait(false);
        AccountForRead(read);
        return read;
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        ValidateReadArguments(buffer, offset, count);
        return ReadArrayAsync(buffer, offset, count, cancellationToken);
    }

    public override int ReadByte()
    {
        EnsureBudgetAvailable();
        var value = inner.ReadByte();
        if (value >= 0)
        {
            AccountForRead(1);
        }

        return value;
    }

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        // The caller owns the supplied stream; this wrapper never closes it.
        base.Dispose(disposing);
    }

    public override ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    private async Task<int> ReadArrayAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        var allowedCount = GetAllowedReadCount(count);
        var read = await inner
            .ReadAsync(buffer.AsMemory(offset, allowedCount), cancellationToken)
            .ConfigureAwait(false);
        AccountForRead(read);
        return read;
    }

    private int GetAllowedReadCount(int requestedCount)
    {
        EnsureBudgetAvailable();

        var remainingWithProbe = maximumBytes - bytesRead + 1;
        return (int)Math.Min(requestedCount, remainingWithProbe);
    }

    private void EnsureBudgetAvailable()
    {
        if (bytesRead > maximumBytes)
        {
            throw new InputLimitExceededException(maximumBytes);
        }
    }

    private void AccountForRead(int read)
    {
        bytesRead += read;
        if (bytesRead > maximumBytes)
        {
            throw new InputLimitExceededException(maximumBytes);
        }
    }

    private static void ValidateReadArguments(
        byte[] buffer,
        int offset,
        int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (buffer.Length - offset < count)
        {
            throw new ArgumentException("The offset and count exceed the buffer bounds.");
        }
    }
}

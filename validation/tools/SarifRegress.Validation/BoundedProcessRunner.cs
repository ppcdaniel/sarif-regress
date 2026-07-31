using System.Collections.Immutable;
using System.Diagnostics;
using System.Text;

namespace SarifRegress.Validation;

/// <summary>Defines one shell-free, bounded child-process invocation.</summary>
public sealed record ProcessInvocation(
    string FileName,
    ImmutableArray<string> Arguments,
    string WorkingDirectory,
    TimeSpan Timeout,
    int MaximumOutputCharacters);

/// <summary>Captures bounded child-process completion without exposing host-specific paths.</summary>
public sealed record ProcessExecutionResult(
    int ExitCode,
    string StandardOutput,
    string StandardError);

/// <summary>Captures exact bounded stdout bytes from a child process.</summary>
public sealed record BinaryProcessExecutionResult(
    int ExitCode,
    byte[] StandardOutput,
    string StandardError);

/// <summary>
/// Runs external tools through <see cref="ProcessStartInfo.ArgumentList"/> with time and output limits.
/// </summary>
public sealed class BoundedProcessRunner
{
    private const int ReadBufferCharacters = 4096;

    /// <summary>Executes one process or kills its tree on timeout/output overflow.</summary>
    public async ValueTask<ProcessExecutionResult> RunAsync(
        ProcessInvocation invocation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        ValidateInvocation(invocation);
        var startInfo = new ProcessStartInfo
        {
            FileName = invocation.FileName,
            WorkingDirectory = invocation.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        foreach (string argument in invocation.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process
        {
            StartInfo = startInfo,
            EnableRaisingEvents = true,
        };
        if (!process.Start())
        {
            throw new InvalidDataException(
                $"External command '{Path.GetFileName(invocation.FileName)}' did not start.");
        }

        process.StandardInput.Close();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(invocation.Timeout);
        Task<string> standardOutput = ReadBoundedAsync(
            process.StandardOutput,
            invocation.MaximumOutputCharacters,
            timeout.Token);
        Task<string> standardError = ReadBoundedAsync(
            process.StandardError,
            invocation.MaximumOutputCharacters,
            timeout.Token);
        try
        {
            await Task.WhenAll(
                    process.WaitForExitAsync(timeout.Token),
                    standardOutput,
                    standardError)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            KillProcessTree(process);
            throw new InvalidDataException(
                $"External command '{Path.GetFileName(invocation.FileName)}' exceeded "
                + $"the {invocation.Timeout.TotalSeconds:0}-second timeout.");
        }
        catch
        {
            KillProcessTree(process);
            throw;
        }

        return new ProcessExecutionResult(
            process.ExitCode,
            await standardOutput.ConfigureAwait(false),
            await standardError.ConfigureAwait(false));
    }

    /// <summary>Executes a process while retaining exact stdout bytes, including invalid UTF-8.</summary>
    public async ValueTask<BinaryProcessExecutionResult> RunBinaryAsync(
        ProcessInvocation invocation,
        int maximumOutputBytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumOutputBytes);
        ValidateInvocation(invocation);
        var startInfo = new ProcessStartInfo
        {
            FileName = invocation.FileName,
            WorkingDirectory = invocation.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        foreach (string argument in invocation.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidDataException(
                $"External command '{Path.GetFileName(invocation.FileName)}' did not start.");
        }

        process.StandardInput.Close();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(invocation.Timeout);
        Task<byte[]> standardOutput = ReadBoundedBytesAsync(
            process.StandardOutput.BaseStream,
            maximumOutputBytes,
            timeout.Token);
        Task<string> standardError = ReadBoundedAsync(
            process.StandardError,
            invocation.MaximumOutputCharacters,
            timeout.Token);
        try
        {
            await Task.WhenAll(
                    process.WaitForExitAsync(timeout.Token),
                    standardOutput,
                    standardError)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            KillProcessTree(process);
            throw new InvalidDataException(
                $"External command '{Path.GetFileName(invocation.FileName)}' exceeded "
                + $"the {invocation.Timeout.TotalSeconds:0}-second timeout.");
        }
        catch
        {
            KillProcessTree(process);
            throw;
        }

        return new BinaryProcessExecutionResult(
            process.ExitCode,
            await standardOutput.ConfigureAwait(false),
            await standardError.ConfigureAwait(false));
    }

    private static async Task<string> ReadBoundedAsync(
        StreamReader reader,
        int maximumCharacters,
        CancellationToken cancellationToken)
    {
        var output = new StringBuilder(Math.Min(maximumCharacters, 16 * 1024));
        char[] buffer = new char[ReadBufferCharacters];
        int charactersRead;
        while ((charactersRead = await reader.ReadAsync(
                   buffer.AsMemory(),
                   cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (output.Length > maximumCharacters - charactersRead)
            {
                throw new InvalidDataException(
                    $"External command output exceeded the {maximumCharacters}-character limit.");
            }

            output.Append(buffer, 0, charactersRead);
        }

        return output.ToString();
    }

    private static async Task<byte[]> ReadBoundedBytesAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream(Math.Min(maximumBytes, 64 * 1024));
        byte[] buffer = new byte[64 * 1024];
        int bytesRead;
        while ((bytesRead = await stream.ReadAsync(
                   buffer.AsMemory(),
                   cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (output.Length > maximumBytes - bytesRead)
            {
                throw new InvalidDataException(
                    $"External command output exceeded the {maximumBytes}-byte limit.");
            }

            output.Write(buffer, 0, bytesRead);
        }

        return output.ToArray();
    }

    private static void ValidateInvocation(ProcessInvocation invocation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(invocation.FileName);
        ArgumentException.ThrowIfNullOrWhiteSpace(invocation.WorkingDirectory);
        if (!Directory.Exists(invocation.WorkingDirectory))
        {
            throw new DirectoryNotFoundException(
                "The external command working directory does not exist.");
        }

        if (invocation.Arguments.Any(argument => argument.Contains('\0')))
        {
            throw new InvalidDataException("An external command argument contains NUL.");
        }

        if (invocation.Timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(invocation.Timeout));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            invocation.MaximumOutputCharacters);
    }

    private static void KillProcessTree(Process process)
    {
        if (process.HasExited)
        {
            return;
        }

        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
            // The process exited between HasExited and Kill; no cleanup remains.
        }
    }
}

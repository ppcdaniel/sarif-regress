namespace SarifRegress.Validation;

using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            ValidationOptions options = ValidationOptionsParser.Parse(args);
            return await new ValidationApplication()
                .RunAsync(options, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (ValidationUsageException exception)
        {
            Console.Error.WriteLine(exception.Message);
            Console.Error.WriteLine();
            Console.Error.WriteLine(ValidationOptionsParser.HelpText);
            return ValidationExitCodes.InvalidInvocation;
        }
        catch (Exception exception) when (
            exception is IOException
            or InvalidDataException
            or JsonException
            or CryptographicException
            or Win32Exception
            or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Holdout validation failed: {exception.Message}");
            return ValidationExitCodes.ValidationFailure;
        }
    }
}

using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SarifRegress.Sarif.Ingestion;

internal sealed class JsonStringLimitExceededException : JsonException
{
    public JsonStringLimitExceededException(int maximumCharacters)
        : base($"A JSON string exceeds the configured {maximumCharacters}-character limit.")
    {
        MaximumCharacters = maximumCharacters;
    }

    public int MaximumCharacters { get; }
}

internal sealed class JsonCollectionLimitExceededException : JsonException
{
    public JsonCollectionLimitExceededException(string collectionKind, long maximumItems)
        : base($"A JSON {collectionKind} exceeds the configured {maximumItems}-item limit.")
    {
        CollectionKind = collectionKind;
        MaximumItems = maximumItems;
    }

    public string CollectionKind { get; }

    public long MaximumItems { get; }
}

internal sealed class UnsupportedJsonValue
{
    private UnsupportedJsonValue()
    {
    }

    public static UnsupportedJsonValue Instance { get; } = new();
}

internal sealed class UnsupportedJsonValueConverter : JsonConverter<UnsupportedJsonValue>
{
    public override UnsupportedJsonValue Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        reader.Skip();
        return UnsupportedJsonValue.Instance;
    }

    public override void Write(
        Utf8JsonWriter writer,
        UnsupportedJsonValue value,
        JsonSerializerOptions options) =>
        throw new NotSupportedException("Unsupported input values are never serialized.");
}

internal sealed class DiscardingObjectConverter : JsonConverter<object>
{
    public override object? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        reader.Skip();
        return UnsupportedJsonValue.Instance;
    }

    public override void Write(
        Utf8JsonWriter writer,
        object value,
        JsonSerializerOptions options) =>
        throw new NotSupportedException("Discarded input values are never serialized.");
}

internal sealed class BoundedStringConverter : JsonConverter<string>
{
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private readonly int maximumCharacters;

    public BoundedStringConverter(int maximumCharacters)
    {
        if (maximumCharacters <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCharacters));
        }

        this.maximumCharacters = maximumCharacters;
    }

    public override string? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType is not JsonTokenType.String and
            not JsonTokenType.PropertyName)
        {
            throw new JsonException("A JSON string token was expected.");
        }

        var rawLength = reader.HasValueSequence
            ? reader.ValueSequence.Length
            : reader.ValueSpan.Length;
        var maximumRawLength = checked((long)maximumCharacters * 6);
        if (rawLength > maximumRawLength)
        {
            throw new JsonStringLimitExceededException(maximumCharacters);
        }

        byte[]? rentedValue = null;
        ReadOnlySpan<byte> rawValue;
        if (reader.HasValueSequence)
        {
            rentedValue = reader.ValueSequence.ToArray();
            rawValue = rentedValue;
        }
        else
        {
            rawValue = reader.ValueSpan;
        }

        int decodedCharacters;
        try
        {
            decodedCharacters = reader.ValueIsEscaped
                ? CountEscapedUtf16Characters(rawValue)
                : StrictUtf8.GetCharCount(rawValue);
        }
        catch (DecoderFallbackException exception)
        {
            throw new JsonException(
                "A JSON string contains invalid UTF-8.",
                exception);
        }
        if (decodedCharacters > maximumCharacters)
        {
            throw new JsonStringLimitExceededException(maximumCharacters);
        }

        var value = reader.GetString();
        if (value?.Length > maximumCharacters)
        {
            throw new JsonStringLimitExceededException(maximumCharacters);
        }

        return value;
    }

    public override void Write(
        Utf8JsonWriter writer,
        string value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(value);

    public override string ReadAsPropertyName(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        Read(ref reader, typeToConvert, options)
        ?? throw new JsonException("A JSON property name cannot be null.");

    public override void WriteAsPropertyName(
        Utf8JsonWriter writer,
        string value,
        JsonSerializerOptions options) =>
        writer.WritePropertyName(value);

    private static int CountEscapedUtf16Characters(ReadOnlySpan<byte> value)
    {
        var characters = 0;
        var segmentStart = 0;
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != (byte)'\\')
            {
                continue;
            }

            characters = checked(
                characters + StrictUtf8.GetCharCount(value[segmentStart..index]));
            if (index + 1 >= value.Length)
            {
                throw new JsonException("A JSON escape sequence is incomplete.");
            }

            characters = checked(characters + 1);
            index += value[index + 1] == (byte)'u' ? 5 : 1;
            segmentStart = index + 1;
        }

        return checked(
            characters + StrictUtf8.GetCharCount(value[segmentStart..]));
    }
}

internal sealed class JsonReadBudget
{
    private readonly int maximumThreadFlowLocationsPerResult;
    private int threadFlowLocationsInCurrentResult;

    public JsonReadBudget(int maximumThreadFlowLocationsPerResult)
    {
        this.maximumThreadFlowLocationsPerResult =
            maximumThreadFlowLocationsPerResult;
    }

    public void BeginResult() => threadFlowLocationsInCurrentResult = 0;

    public void AddThreadFlowLocation()
    {
        if (threadFlowLocationsInCurrentResult >=
            maximumThreadFlowLocationsPerResult)
        {
            throw new JsonCollectionLimitExceededException(
                "thread-flow location collection",
                maximumThreadFlowLocationsPerResult);
        }
        threadFlowLocationsInCurrentResult++;
    }
}

internal sealed class BoundedListConverterFactory : JsonConverterFactory
{
    private readonly Func<Type, int> maximumForElement;
    private readonly JsonReadBudget? budget;

    public BoundedListConverterFactory(
        Func<Type, int> maximumForElement,
        JsonReadBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(maximumForElement);
        this.maximumForElement = maximumForElement;
        this.budget = budget;
    }

    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsGenericType &&
        typeToConvert.GetGenericTypeDefinition() == typeof(List<>);

    public override JsonConverter CreateConverter(
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        var elementType = typeToConvert.GetGenericArguments()[0];
        var converterType = typeof(BoundedListConverter<>).MakeGenericType(elementType);
        return (JsonConverter)Activator.CreateInstance(
            converterType,
            maximumForElement(elementType),
            budget)!;
    }

    private sealed class BoundedListConverter<T> : JsonConverter<List<T>>
    {
        private readonly int maximumItems;
        private readonly JsonReadBudget? budget;

        public BoundedListConverter(int maximumItems, JsonReadBudget? budget)
        {
            this.maximumItems = maximumItems;
            this.budget = budget;
        }

        public override List<T>? Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Null)
            {
                return null;
            }

            if (reader.TokenType != JsonTokenType.StartArray)
            {
                throw new JsonException("A JSON array was expected.");
            }

            var values = new List<T>();
            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                if (values.Count >= maximumItems)
                {
                    throw new JsonCollectionLimitExceededException(
                        "array",
                        maximumItems);
                }

                if (typeof(T) == typeof(SarifResultWire))
                {
                    budget?.BeginResult();
                }

                if (typeof(T) == typeof(SarifThreadFlowLocationWire))
                {
                    budget?.AddThreadFlowLocation();
                }

                values.Add(JsonSerializer.Deserialize<T>(ref reader, options)!);
            }

            if (reader.TokenType != JsonTokenType.EndArray)
            {
                throw new JsonException("A JSON array was not terminated.");
            }

            return values;
        }

        public override void Write(
            Utf8JsonWriter writer,
            List<T> value,
            JsonSerializerOptions options) =>
            throw new NotSupportedException("Bounded input lists are never serialized.");
    }
}

internal sealed class BoundedStringDictionaryConverterFactory : JsonConverterFactory
{
    private readonly int maximumItems;

    public BoundedStringDictionaryConverterFactory(int maximumItems)
    {
        this.maximumItems = maximumItems;
    }

    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsGenericType &&
        typeToConvert.GetGenericTypeDefinition() == typeof(Dictionary<,>) &&
        typeToConvert.GetGenericArguments()[0] == typeof(string);

    public override JsonConverter CreateConverter(
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        var valueType = typeToConvert.GetGenericArguments()[1];
        var converterType = typeof(BoundedDictionaryConverter<>)
            .MakeGenericType(valueType);
        return (JsonConverter)Activator.CreateInstance(
            converterType,
            maximumItems)!;
    }

    private sealed class BoundedDictionaryConverter<TValue>
        : JsonConverter<Dictionary<string, TValue>>
    {
        private readonly int maximumItems;

        public BoundedDictionaryConverter(int maximumItems)
        {
            this.maximumItems = maximumItems;
        }

        public override Dictionary<string, TValue>? Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Null)
            {
                return null;
            }

            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException("A JSON object was expected.");
            }

            var values = new Dictionary<string, TValue>(StringComparer.Ordinal);
            var stringConverter = (JsonConverter<string>)options
                .GetConverter(typeof(string));
            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException("A JSON property name was expected.");
                }

                if (values.Count >= maximumItems)
                {
                    throw new JsonCollectionLimitExceededException(
                        "object",
                        maximumItems);
                }

                var propertyName = stringConverter.ReadAsPropertyName(
                    ref reader,
                    typeof(string),
                    options);
                if (!reader.Read())
                {
                    throw new JsonException("A JSON object value is missing.");
                }

                var value = JsonSerializer.Deserialize<TValue>(
                    ref reader,
                    options)!;
                if (!values.TryAdd(propertyName, value))
                {
                    throw new JsonException(
                        $"The JSON object contains duplicate property \"{propertyName}\".");
                }
            }

            if (reader.TokenType != JsonTokenType.EndObject)
            {
                throw new JsonException("A JSON object was not terminated.");
            }

            return values;
        }

        public override void Write(
            Utf8JsonWriter writer,
            Dictionary<string, TValue> value,
            JsonSerializerOptions options) =>
            throw new NotSupportedException("Bounded input objects are never serialized.");
    }
}

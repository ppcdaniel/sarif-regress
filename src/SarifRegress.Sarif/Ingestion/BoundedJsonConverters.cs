using System.Buffers;
using System.Reflection;
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

internal sealed class BoundedJsonReadConstraints
{
    public BoundedJsonReadConstraints(
        int maximumDepth,
        int maximumCollectionItems,
        int maximumStringCharacters,
        CancellationToken cancellationToken)
    {
        if (maximumDepth <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDepth));
        }

        if (maximumCollectionItems <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumCollectionItems));
        }

        if (maximumStringCharacters <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumStringCharacters));
        }

        MaximumDepth = maximumDepth;
        MaximumCollectionItems = maximumCollectionItems;
        MaximumStringCharacters = maximumStringCharacters;
        CancellationToken = cancellationToken;
    }

    public int MaximumDepth { get; }

    public int MaximumCollectionItems { get; }

    public int MaximumStringCharacters { get; }

    public CancellationToken CancellationToken { get; }

    public void CheckToken() => CancellationToken.ThrowIfCancellationRequested();

    public void CheckContainerDepth(ref Utf8JsonReader reader)
    {
        if (reader.CurrentDepth + 1 > MaximumDepth)
        {
            throw new JsonException(
                $"The JSON input exceeds the configured {MaximumDepth}-level depth limit.");
        }
    }
}

internal static class BoundedJsonTraversal
{
    public static void Skip(
        ref Utf8JsonReader reader,
        BoundedJsonReadConstraints constraints)
    {
        ArgumentNullException.ThrowIfNull(constraints);
        SkipValue(ref reader, constraints);
    }

    private static void SkipValue(
        ref Utf8JsonReader reader,
        BoundedJsonReadConstraints constraints)
    {
        constraints.CheckToken();
        switch (reader.TokenType)
        {
            case JsonTokenType.StartObject:
                constraints.CheckContainerDepth(ref reader);
                SkipObject(ref reader, constraints);
                return;

            case JsonTokenType.StartArray:
                constraints.CheckContainerDepth(ref reader);
                SkipArray(ref reader, constraints);
                return;

            case JsonTokenType.String:
            case JsonTokenType.PropertyName:
                _ = BoundedStringConverter.ReadBounded(
                    ref reader,
                    constraints.MaximumStringCharacters,
                    constraints.CancellationToken);
                return;

            case JsonTokenType.Null:
            case JsonTokenType.True:
            case JsonTokenType.False:
            case JsonTokenType.Number:
                return;

            default:
                throw new JsonException(
                    "A complete JSON value was expected.");
        }
    }

    private static void SkipObject(
        ref Utf8JsonReader reader,
        BoundedJsonReadConstraints constraints)
    {
        var propertyCount = 0;
        while (reader.Read())
        {
            constraints.CheckToken();
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return;
            }

            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException(
                    "A JSON property name was expected.");
            }

            if (propertyCount >= constraints.MaximumCollectionItems)
            {
                throw new JsonCollectionLimitExceededException(
                    "object",
                    constraints.MaximumCollectionItems);
            }

            propertyCount++;
            _ = BoundedStringConverter.ReadBounded(
                ref reader,
                constraints.MaximumStringCharacters,
                constraints.CancellationToken);
            if (!reader.Read())
            {
                throw new JsonException("A JSON object value is missing.");
            }

            SkipValue(ref reader, constraints);
        }

        throw new JsonException("A JSON object was not terminated.");
    }

    private static void SkipArray(
        ref Utf8JsonReader reader,
        BoundedJsonReadConstraints constraints)
    {
        var itemCount = 0;
        while (reader.Read())
        {
            constraints.CheckToken();
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                return;
            }

            if (itemCount >= constraints.MaximumCollectionItems)
            {
                throw new JsonCollectionLimitExceededException(
                    "array",
                    constraints.MaximumCollectionItems);
            }

            itemCount++;
            SkipValue(ref reader, constraints);
        }

        throw new JsonException("A JSON array was not terminated.");
    }
}

internal sealed class UnsupportedJsonValueConverter : JsonConverter<UnsupportedJsonValue>
{
    private readonly BoundedJsonReadConstraints constraints;

    public UnsupportedJsonValueConverter(
        BoundedJsonReadConstraints constraints)
    {
        ArgumentNullException.ThrowIfNull(constraints);
        this.constraints = constraints;
    }

    public override UnsupportedJsonValue Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        BoundedJsonTraversal.Skip(ref reader, constraints);
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
    private readonly BoundedJsonReadConstraints constraints;

    public DiscardingObjectConverter(BoundedJsonReadConstraints constraints)
    {
        ArgumentNullException.ThrowIfNull(constraints);
        this.constraints = constraints;
    }

    public override object? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        BoundedJsonTraversal.Skip(ref reader, constraints);
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
    private readonly CancellationToken cancellationToken;

    public BoundedStringConverter(
        int maximumCharacters,
        CancellationToken cancellationToken = default)
    {
        if (maximumCharacters <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCharacters));
        }

        this.maximumCharacters = maximumCharacters;
        this.cancellationToken = cancellationToken;
    }

    public override string? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        return ReadBounded(
            ref reader,
            maximumCharacters,
            cancellationToken);
    }

    internal static string? ReadBounded(
        ref Utf8JsonReader reader,
        int maximumCharacters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        ValidateBounded(
            ref reader,
            maximumCharacters,
            cancellationToken);
        var value = reader.GetString();
        if (value?.Length > maximumCharacters)
        {
            throw new JsonStringLimitExceededException(maximumCharacters);
        }

        return value;
    }

    internal static void ValidateBounded(
        ref Utf8JsonReader reader,
        int maximumCharacters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
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
                ? CountEscapedUtf16Characters(
                    rawValue,
                    cancellationToken)
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

    private static int CountEscapedUtf16Characters(
        ReadOnlySpan<byte> value,
        CancellationToken cancellationToken)
    {
        var characters = 0;
        var segmentStart = 0;
        for (var index = 0; index < value.Length; index++)
        {
            if ((index & 1023) == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

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
    private const string ThreadFlowCollectionKind =
        "thread-flow collection";
    private const string ThreadFlowLocationCollectionKind =
        "thread-flow location collection";
    private readonly int maximumThreadFlowItemsPerResult;
    private readonly CancellationToken cancellationToken;
    private int threadFlowsInCurrentResult;
    private int threadFlowLocationsInCurrentResult;

    public JsonReadBudget(
        int maximumThreadFlowItemsPerResult,
        CancellationToken cancellationToken)
    {
        this.maximumThreadFlowItemsPerResult =
            maximumThreadFlowItemsPerResult;
        this.cancellationToken = cancellationToken;
    }

    public void BeginResult()
    {
        cancellationToken.ThrowIfCancellationRequested();
        threadFlowsInCurrentResult = 0;
        threadFlowLocationsInCurrentResult = 0;
    }

    public void AddThreadFlow() =>
        AddItem(
            ref threadFlowsInCurrentResult,
            ThreadFlowCollectionKind);

    public void AddThreadFlowLocation()
    {
        AddItem(
            ref threadFlowLocationsInCurrentResult,
            ThreadFlowLocationCollectionKind);
    }

    private void AddItem(ref int currentCount, string collectionKind)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (currentCount >= maximumThreadFlowItemsPerResult)
        {
            throw new JsonCollectionLimitExceededException(
                collectionKind,
                maximumThreadFlowItemsPerResult);
        }

        currentCount++;
    }
}

internal sealed class BoundedListConverterFactory : JsonConverterFactory
{
    private readonly Func<Type, int> maximumForElement;
    private readonly JsonReadBudget? budget;
    private readonly BoundedJsonReadConstraints constraints;

    public BoundedListConverterFactory(
        Func<Type, int> maximumForElement,
        BoundedJsonReadConstraints constraints,
        JsonReadBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(maximumForElement);
        ArgumentNullException.ThrowIfNull(constraints);
        this.maximumForElement = maximumForElement;
        this.constraints = constraints;
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
            constraints,
            budget)!;
    }

    private sealed class BoundedListConverter<T> : JsonConverter<List<T>>
    {
        private readonly int maximumItems;
        private readonly BoundedJsonReadConstraints constraints;
        private readonly JsonReadBudget? budget;

        public BoundedListConverter(
            int maximumItems,
            BoundedJsonReadConstraints constraints,
            JsonReadBudget? budget)
        {
            this.maximumItems = maximumItems;
            this.constraints = constraints;
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

            constraints.CheckContainerDepth(ref reader);
            var values = new List<T>();
            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                constraints.CheckToken();
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

                if (typeof(T) == typeof(SarifThreadFlowWire))
                {
                    budget?.AddThreadFlow();
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
    private readonly BoundedJsonReadConstraints constraints;

    public BoundedStringDictionaryConverterFactory(
        int maximumItems,
        BoundedJsonReadConstraints constraints)
    {
        ArgumentNullException.ThrowIfNull(constraints);
        this.maximumItems = maximumItems;
        this.constraints = constraints;
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
            maximumItems,
            constraints)!;
    }

    private sealed class BoundedDictionaryConverter<TValue>
        : JsonConverter<Dictionary<string, TValue>>
    {
        private readonly int maximumItems;
        private readonly BoundedJsonReadConstraints constraints;

        public BoundedDictionaryConverter(
            int maximumItems,
            BoundedJsonReadConstraints constraints)
        {
            this.maximumItems = maximumItems;
            this.constraints = constraints;
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

            constraints.CheckContainerDepth(ref reader);
            var values = new Dictionary<string, TValue>(StringComparer.Ordinal);
            var stringConverter = (JsonConverter<string>)options
                .GetConverter(typeof(string));
            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                constraints.CheckToken();
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

internal sealed class BoundedJsonObjectConverterFactory : JsonConverterFactory
{
    private readonly Func<Type, bool> canConvert;
    private readonly BoundedJsonReadConstraints constraints;

    public BoundedJsonObjectConverterFactory(
        Func<Type, bool> canConvert,
        BoundedJsonReadConstraints constraints)
    {
        ArgumentNullException.ThrowIfNull(canConvert);
        ArgumentNullException.ThrowIfNull(constraints);
        this.canConvert = canConvert;
        this.constraints = constraints;
    }

    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsClass && canConvert(typeToConvert);

    public override JsonConverter CreateConverter(
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        var converterType = typeof(BoundedJsonObjectConverter<>)
            .MakeGenericType(typeToConvert);
        return (JsonConverter)Activator.CreateInstance(
            converterType,
            constraints)!;
    }

    private sealed class BoundedJsonObjectConverter<T> : JsonConverter<T>
        where T : class
    {
        private readonly BoundedJsonReadConstraints constraints;
        private readonly KnownProperty[] properties;
        private readonly PropertyInfo? extensionDataProperty;

        public BoundedJsonObjectConverter(
            BoundedJsonReadConstraints constraints)
        {
            this.constraints = constraints;
            var objectProperties = typeof(T).GetProperties(
                BindingFlags.Instance | BindingFlags.Public);
            extensionDataProperty = objectProperties.SingleOrDefault(
                property => property.GetCustomAttribute<
                    JsonExtensionDataAttribute>() is not null);
            var propertyEntries = objectProperties
                .Where(property =>
                    property != extensionDataProperty &&
                    property.SetMethod is not null)
                .Select(property => new
                {
                    Name = property.GetCustomAttribute<
                        JsonPropertyNameAttribute>()?.Name ?? property.Name,
                    Property = property,
                })
                .ToArray();
            if (propertyEntries.Length > sizeof(ulong) * 8)
            {
                throw new InvalidOperationException(
                    $"The bounded JSON object type {typeof(T).Name} has too many properties.");
            }

            properties = propertyEntries
                .Select(
                    (item, index) => new KnownProperty(
                        item.Name,
                        Encoding.UTF8.GetBytes(item.Name),
                        item.Property,
                        1UL << index))
                .ToArray();
        }

        public override T? Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            constraints.CheckToken();
            if (reader.TokenType == JsonTokenType.Null)
            {
                return null;
            }

            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException("A JSON object was expected.");
            }

            constraints.CheckContainerDepth(ref reader);
            var value = (T?)Activator.CreateInstance(
                typeof(T),
                nonPublic: true)
                ?? throw new JsonException(
                    $"The JSON object type {typeof(T).Name} cannot be created.");
            Dictionary<string, object?>? extensionData = null;
            HashSet<string>? seenUnknownProperties = null;
            ulong seenKnownProperties = 0;
            var propertyCount = 0;
            while (reader.Read() &&
                reader.TokenType != JsonTokenType.EndObject)
            {
                constraints.CheckToken();
                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException(
                        "A JSON property name was expected.");
                }

                if (propertyCount >= constraints.MaximumCollectionItems)
                {
                    throw new JsonCollectionLimitExceededException(
                        "object",
                        constraints.MaximumCollectionItems);
                }

                propertyCount++;
                BoundedStringConverter.ValidateBounded(
                    ref reader,
                    constraints.MaximumStringCharacters,
                    constraints.CancellationToken);
                if (TryGetKnownProperty(ref reader, out var property))
                {
                    if ((seenKnownProperties & property.SeenMask) != 0)
                    {
                        throw DuplicateProperty(property.JsonName);
                    }

                    seenKnownProperties |= property.SeenMask;
                    if (!reader.Read())
                    {
                        throw new JsonException(
                            "A JSON object value is missing.");
                    }

                    var propertyValue = JsonSerializer.Deserialize(
                        ref reader,
                        property.Property.PropertyType,
                        options);
                    property.Property.SetValue(value, propertyValue);
                    continue;
                }

                var propertyName = reader.GetString()
                    ?? throw new JsonException(
                        "A JSON property name cannot be null.");
                seenUnknownProperties ??= new HashSet<string>(
                    StringComparer.Ordinal);
                if (!seenUnknownProperties.Add(propertyName))
                {
                    throw DuplicateProperty(propertyName);
                }

                if (!reader.Read())
                {
                    throw new JsonException(
                        "A JSON object value is missing.");
                }

                BoundedJsonTraversal.Skip(ref reader, constraints);
                if (extensionDataProperty is not null)
                {
                    extensionData ??= new Dictionary<string, object?>(
                        StringComparer.Ordinal);
                    extensionData.Add(
                        propertyName,
                        UnsupportedJsonValue.Instance);
                }
            }

            if (reader.TokenType != JsonTokenType.EndObject)
            {
                throw new JsonException(
                    "A JSON object was not terminated.");
            }

            extensionDataProperty?.SetValue(value, extensionData);
            return value;
        }

        private bool TryGetKnownProperty(
            ref Utf8JsonReader reader,
            out KnownProperty property)
        {
            foreach (var candidate in properties)
            {
                if (reader.ValueTextEquals(candidate.Utf8Name))
                {
                    property = candidate;
                    return true;
                }
            }

            property = default;
            return false;
        }

        private static JsonException DuplicateProperty(string propertyName) =>
            new(
                $"The JSON object contains duplicate property \"{propertyName}\".");

        public override void Write(
            Utf8JsonWriter writer,
            T value,
            JsonSerializerOptions options) =>
            throw new NotSupportedException(
                "Bounded input objects are never serialized.");

        private readonly record struct KnownProperty(
            string JsonName,
            byte[] Utf8Name,
            PropertyInfo Property,
            ulong SeenMask);
    }
}

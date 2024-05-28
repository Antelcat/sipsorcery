using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace SIPSorcery.Interfaces;

public interface IJsonify;

public static class JsonifyExtensions
{
    public static string ToJson<T>(this T obj) where T : IJsonify
        => JsonSerializer.Serialize(obj);
    
    public static T? FromJson<T>(this string json) where T : IJsonify
    {
        try
        {
            return JsonSerializer.Deserialize<T>(json);
        }
        catch
        {
            return default;
        }
    }
    
    public static bool TryFromJson<T>(this string json, [NotNullWhen(true)] out T? jsonify) where T : IJsonify
    {
        try
        {
            jsonify = JsonSerializer.Deserialize<T>(json);
            return !EqualityComparer<T?>.Default.Equals(jsonify, default);
        }
        catch
        {
            jsonify = default;
            return false;
        }
    }
}
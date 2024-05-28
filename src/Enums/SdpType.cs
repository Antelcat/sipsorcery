using System.Text.Json.Serialization;

namespace SIPSorcery.SIP.App;

/// <summary>
/// The type of the SDP packet being set.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum SdpType
{
    [JsonPropertyName("answer")] Answer = 0,
    [JsonPropertyName("offer")] Offer = 1
}

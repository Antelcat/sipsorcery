//-----------------------------------------------------------------------------
// Filename: SIPEndPoint.cs
//
// Description: Represents what needs to be known about a SIP end point for 
// network communications.
//
// Author(s):
// Aaron Clauson
//
// History:
// 14 Oct 2019	Aaron Clauson	Added missing header.
// 07 Nov 2019  Aaron Clauson   Added ConnectionID property.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Net;
using System.Net.Sockets;
using SIPSorcery.Sys;

namespace SIPSorcery.SIP;

/// <summary>
/// This class is a more specific version of the SIPURI class BUT is only concerned with the network and
/// transport properties. It contains all the information needed to determine the remote end point to
/// deliver a SIP request or response to.
/// 
/// This class must remain immutable otherwise the SIP stack can develop problems. SIP end points can get
/// passed amongst different servers for logging and forwarding SIP messages and a modification of the end point
/// by one server can result in a problem for a different server. Instead a new SIP end point should be created
/// wherever a modification is required.
/// </summary>
public record SIPEndPoint
{
    private const string CHANNELID_ATTRIBUTE_NAME = "cid";
    private const string CONNECTIONID_ATTRIBUTE_NAME = "xid";

    public static SIPEndPoint Empty { get; } = new();

    /// <summary>
    /// The transport/application layer protocol the SIP end point is using.
    /// </summary>
    public SIPProtocolsEnum Protocol { get; init; } = SIPProtocolsEnum.udp;

    /// <summary>
    /// The network address for the SIP end point. IPv4 and IPv6 are supported.
    /// </summary>
    public IPAddress Address { get; init; }

    /// <summary>
    /// The network port for the SIP end point.
    /// </summary>
    public int Port { get; init; }

    /// <summary>
    /// For connection oriented transport protocols such as TCP, TLS and WebSockets this
    /// ID can record the unique connection a SIP message was received on. This makes it 
    /// possible to ensure responses or subsequent request can re-use the same connection.
    /// </summary>
    public string? ConnectionID { get; init; }

    /// <summary>
    /// If set represents the SIP channel ID that this SIP end point was created from.
    /// </summary>
    public string? ChannelID { get; init; }

    private SIPEndPoint() { }

    public SIPEndPoint(IPEndPoint endPoint, SIPProtocolsEnum protocol = SIPProtocolsEnum.udp, string? channelID = null, string? connectionID = null)
        : this(endPoint.Address, endPoint.Port, protocol, channelID, connectionID)
    {
    }

    /// <summary>
    /// Instantiates a new SIP end point.
    /// </summary>
    /// <param name="address">The network address.</param>
    /// <param name="protocol">The SIP transport/application protocol used for the transmission.</param>
    /// <param name="port">The network port.</param>
    /// <param name="channelID">Optional. The unique ID of the channel that created the end point.</param>
    /// <param name="connectionID">Optional. For connection oriented protocols the unique ID of the connection.
    /// For connectionless protocols should be set to null.</param>
    public SIPEndPoint(
        IPAddress address,
        int port = 0,
        SIPProtocolsEnum protocol = SIPProtocolsEnum.udp,
        string? channelID = null,
        string? connectionID = null)
    {
        Address = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        Port = port == 0 ? SIPConstants.GetDefaultPort(Protocol) : port;
        Protocol = protocol;
        ChannelID = channelID;
        ConnectionID = connectionID;
    }

    public SIPEndPoint(SIPURI sipUri)
    {
        Protocol = sipUri.Protocol;

        if (!IPSocket.TryParseIPEndPoint(sipUri.Host, out var endPoint))
        {
            throw new ApplicationException($"Could not parse SIPURI host {sipUri.Host} as an IP end point.");
        }

        Address = endPoint.Address.IsIPv4MappedToIPv6 ? endPoint.Address.MapToIPv4() : endPoint.Address;
        Port = endPoint.Port == 0 ? SIPConstants.GetDefaultPort(Protocol) : endPoint.Port;
    }

    /// <summary>
    /// Parses a SIP end point from either a serialised SIP end point string, format of:
    /// (udp|tcp|tls|ws|wss):(IPEndpoint)[;connid=abcd]
    /// or from a string that represents a SIP URI.
    /// </summary>
    /// <param name="sipEndPointStr">The string to parse to extract the SIP end point.</param>
    /// <returns>If successful a SIPEndPoint object or null otherwise.</returns>
    public static SIPEndPoint? Parse(string sipEndPointStr)
    {
        if (sipEndPointStr.IsNullOrBlank())
        {
            return null;
        }

        if (sipEndPointStr.ToLower().StartsWith("udp:") ||
            sipEndPointStr.ToLower().StartsWith("tcp:") ||
            sipEndPointStr.ToLower().StartsWith("tls:") ||
            sipEndPointStr.ToLower().StartsWith("ws:") ||
            sipEndPointStr.ToLower().StartsWith("wss:"))
        {
            return ParseSerialisedSIPEndPoint(sipEndPointStr);
        }
        
        return SIPURI.ParseSIPURIRelaxed(sipEndPointStr)?.ToSIPEndPoint();
    }

    /// <summary>
    /// Reverses The SIPEndPoint.ToString() method. 
    /// </summary>
    /// <param name="serialisedSIPEndPoint">The serialised SIP end point MUST be in the form protocol:socket[;connid=abcd].
    /// Valid examples are udp:10.0.0.1:5060 and ws:10.0.0.1:5060;connid=abcd. An invalid example is 10.0.0.1:5060.</param>
    private static SIPEndPoint ParseSerialisedSIPEndPoint(string serialisedSIPEndPoint)
    {
        string? channelID = null;
        string? connectionID = null;
        string? endPointStr = null;
        var protocolStr = serialisedSIPEndPoint[..serialisedSIPEndPoint.IndexOf(':')];

        if (serialisedSIPEndPoint.Contains(";"))
        {
            endPointStr = serialisedSIPEndPoint.Slice(':', ';');
            var paramsStr = serialisedSIPEndPoint[(serialisedSIPEndPoint.IndexOf(';') + 1)..].Trim();

            var endPointParams = new SIPParameters(paramsStr, ';');

            if (endPointParams.Has(CHANNELID_ATTRIBUTE_NAME))
            {
                channelID = endPointParams.Get(CHANNELID_ATTRIBUTE_NAME);
            }

            if (endPointParams.Has(CONNECTIONID_ATTRIBUTE_NAME))
            {
                connectionID = endPointParams.Get(CONNECTIONID_ATTRIBUTE_NAME);
            }
        }
        else
        {
            endPointStr = serialisedSIPEndPoint[(serialisedSIPEndPoint.IndexOf(':') + 1)..];
        }

        if (!IPSocket.TryParseIPEndPoint(endPointStr, out var endPoint))
        {
            throw new ApplicationException($"Could not parse SIPEndPoint host {endPointStr} as an IP end point.");
        }

        return new SIPEndPoint(endPoint, SIPProtocolsType.GetProtocolType(protocolStr), channelID, connectionID);
    }

    public override string ToString()
    {
        return $"{Protocol}:{new IPEndPoint(Address, Port)}";
    }
    
    /// <summary>
    /// Get the IP end point from the SIP end point
    /// </summary>
    /// <param name="mapIpv4ToIpv6">Set to true if a resultant IPv4 end point should be mapped to IPv6.
    /// This is required in some cases when using dual mode sockets. For example Mono requires that a destination IP
    /// end point for a dual mode socket is set as IPv6.</param>
    /// <returns>An IP end point.</returns>
    public IPEndPoint GetIPEndPoint(bool mapIpv4ToIpv6 = false)
    {
        if (mapIpv4ToIpv6 && Address.AddressFamily == AddressFamily.InterNetwork)
        {
            return new IPEndPoint(Address.MapToIPv6(), Port);
        }
        else
        {
            return new IPEndPoint(Address, Port);
        }
    }

    /// <summary>
    /// Determines whether the socket destination for two different SIP end points are equal.
    /// </summary>
    /// <param name="endPoint1">First end point to compare.</param>
    /// <param name="endPoint2">Second end point to compare.</param>
    /// <returns>True if the end points both resolve to the same protocol and IP end point.</returns>
    public static bool AreSocketsEqual(SIPEndPoint endPoint1, SIPEndPoint endPoint2)
    {
        var ep1Address = endPoint1.Address.IsIPv4MappedToIPv6 ? endPoint1.Address.MapToIPv4() : endPoint1.Address;
        var ep2Address = endPoint2.Address.IsIPv4MappedToIPv6 ? endPoint2.Address.MapToIPv4() : endPoint2.Address;

        return endPoint1.Protocol == endPoint2.Protocol &&
               endPoint1.Port == endPoint2.Port &&
               ep1Address.Equals(ep2Address);
    }

    public bool IsSocketEqual(SIPEndPoint endPoint)
    {
        return AreSocketsEqual(this, endPoint);
    }
}

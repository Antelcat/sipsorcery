//-----------------------------------------------------------------------------
// Filename: RTCDataChannel.cs
//
// Description: Contains an implementation for a WebRTC data channel.
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
//
// History:
// 13 Jul 2020	Aaron Clauson	Created.
// 22 Mar 2021  Aaron Clauson   Refactored for new SCTP implementation.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    /// <summary>
    /// The assignments for SCTP payload protocol IDs used with
    /// WebRTC data channels.
    /// </summary>
    /// <remarks>
    /// See https://tools.ietf.org/html/rfc8831#section-8
    /// </remarks>
    public enum DataChannelPayloadProtocols : uint
    {
        WebRTC_DCEP = 50, // Data Channel Establishment Protocol (DCEP).
        WebRTC_String = 51,
        [Obsolete]
        WebRTC_Binary_Partial = 52, // Deprecated.
        WebRTC_Binary = 53,
        [Obsolete]
        WebRTC_String_Partial = 54, // Deprecated.
        WebRTC_String_Empty = 56,
        WebRTC_Binary_Empty = 57
    }

    /// <summary>
    /// A WebRTC data channel is generic transport service
    /// that allows peers to exchange generic data in a peer
    /// to peer manner.
    /// </summary>
    public class RTCDataChannel(RTCSctpTransport transport, RTCDataChannelInit? init = null) : IRTCDataChannel
    {
        private static ILogger logger = Log.Logger;

        public string Label { get; init; } = "<None>";

        public bool Ordered { get; } = init?.Ordered ?? true;

        public ushort? MaxPacketLifeTime { get; } = init?.MaxPacketLifeTime;

        public ushort? MaxRetransmits { get; } = init?.MaxRetransmits;

        public string Protocol { get; } = init?.Protocol ?? string.Empty;

        public bool Negotiated { get; } = init?.Negotiated ?? false;

        public ushort? Id { get; internal set; } = init?.Id;

        public RTCDataChannelState ReadyState { get; internal set; } = RTCDataChannelState.connecting;

        public ulong BufferedAmount => transport.RTCSctpAssociation.SendBufferedAmount;

        public ulong BufferedAmountLowThreshold { get; set; }

        public string BinaryType { get; set; } = "arraybuffer";

        public uint MaxMessageSize => transport.MaxMessageSize;

        public string? Error { get; private set; }

        public bool IsOpened { get; internal set; }

        private readonly RTCSctpTransport? transport = transport;

        public event Action? OnOpen;

        //public event Action onbufferedamountlow;
        public event Action<string>? OnError;

        //public event Action onclosing;
        public event Action? OnClose;
        public event OnDataChannelMessageDelegate? OnMessage;

        internal void GotAck()
        {
            logger.LogDebug($"Data channel for label {Label} now open.");
            IsOpened = true;
            ReadyState = RTCDataChannelState.open;
            OnOpen?.Invoke();
        }

        /// <summary>
        /// Sets the error message is there was a problem creating the data channel.
        /// </summary>
        internal void SetError(string error)
        {
            Error = error;
            OnError?.Invoke(error);
        }

        public void close()
        {
            IsOpened = false;
            ReadyState = RTCDataChannelState.closed;
            logger.LogDebug($"Data channel with id {Id} has been closed");
            OnClose?.Invoke();
        }

        /// <summary>
        /// Sends a string data payload on the data channel.
        /// </summary>
        /// <param name="message">The string message to send.</param>
        public void send(string message)
        {
            if (message != null && Encoding.UTF8.GetByteCount(message) > transport.MaxMessageSize)
            {
                throw new ApplicationException(
                    $"Data channel {Label} was requested to send data of length {Encoding.UTF8.GetByteCount(message)} " +
                    $" that exceeded the maximum allowed message size of {transport.MaxMessageSize}.");
            }
            
            if (transport.State != RTCSctpTransportState.Connected)
            {
                logger.LogWarning($"WebRTC data channel send failed due to SCTP transport in state {transport.State}.");
            }
            else
            {
                lock (this)
                {
                    if (string.IsNullOrEmpty(message))
                    {
                        transport.RTCSctpAssociation.SendData(Id.GetValueOrDefault(),
                            (uint)DataChannelPayloadProtocols.WebRTC_String_Empty,
                            [0x00]);
                    }
                    else
                    {
                        transport.RTCSctpAssociation.SendData(Id.GetValueOrDefault(),
                            (uint)DataChannelPayloadProtocols.WebRTC_String,
                            Encoding.UTF8.GetBytes(message));
                    }
                }
            }
        }

        /// <summary>
        /// Sends a binary data payload on the data channel.
        /// </summary>
        /// <param name="data">The data to send.</param>
        public void send(byte[] data)
        {
            if (data.Length > transport.MaxMessageSize)
            {
                throw new ApplicationException(
                    $"Data channel {Label} was requested to send data of length {data.Length} " +
                    $" that exceeded the maximum allowed message size of {transport.MaxMessageSize}.");
            }

            if (transport.State != RTCSctpTransportState.Connected)
            {
                logger.LogWarning($"WebRTC data channel send failed due to SCTP transport in state {transport.State}.");
            }
            else
            {
                lock (this)
                {
                    if (data.Length == 0)
                    {
                        transport.RTCSctpAssociation.SendData(Id.GetValueOrDefault(),
                            (uint)DataChannelPayloadProtocols.WebRTC_Binary_Empty,
                            [0x00]);
                    }
                    else
                    {
                        transport.RTCSctpAssociation.SendData(Id.GetValueOrDefault(),
                            (uint)DataChannelPayloadProtocols.WebRTC_Binary,
                            data);
                    }
                }
            }
        }

        /// <summary>
        /// Sends an OPEN Data Channel Establishment Protocol (DCEP) message
        /// to open a data channel on the remote peer for send/receive.
        /// </summary>
        internal void SendDcepOpen()
        {
            byte type = (byte)DataChannelTypes.DATA_CHANNEL_RELIABLE;
            if (!Ordered)
            {
                type += (byte)DataChannelTypes.DATA_CHANNEL_RELIABLE_UNORDERED;
            }
            if (MaxPacketLifeTime > 0)
            {
                type += (byte)DataChannelTypes.DATA_CHANNEL_PARTIAL_RELIABLE_TIMED;
            }
            else if (MaxRetransmits > 0)
            {
                type += (byte)DataChannelTypes.DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT;
            }

            var dcepOpen = new DataChannelOpenMessage
            {
                MessageType = (byte)DataChannelMessageTypes.OPEN,
                ChannelType = type,
                Label = Label,
                Protocol = Protocol,
            };

            lock (this)
            {
                transport.RTCSctpAssociation.SendData(Id.GetValueOrDefault(),
                    (uint)DataChannelPayloadProtocols.WebRTC_DCEP,
                    dcepOpen.GetBytes());
            }
        }

        /// <summary>
        /// Sends an ACK response for a Data Channel Establishment Protocol (DCEP)
        /// control message.
        /// </summary>
        internal void SendDcepAck()
        {
            lock (this)
            {
                transport.RTCSctpAssociation.SendData(Id.GetValueOrDefault(),
                    (uint)DataChannelPayloadProtocols.WebRTC_DCEP,
                    [(byte)DataChannelMessageTypes.ACK]);
            }
        }

        /// <summary>
        /// Event handler for an SCTP data chunk being received for this data channel.
        /// </summary>
        internal void GotData(ushort streamID, ushort streamSeqNum, uint ppID, byte[] data)
        {
            //logger.LogTrace($"WebRTC data channel GotData stream ID {streamID}, stream seqnum {streamSeqNum}, ppid {ppID}, label {label}.");

            // If the ppID is not recognised default to binary.
            var payloadType = DataChannelPayloadProtocols.WebRTC_Binary;

            if (Enum.IsDefined(typeof(DataChannelPayloadProtocols), ppID))
            {
                payloadType = (DataChannelPayloadProtocols)ppID;
            }

            OnMessage?.Invoke(this, payloadType, data);
        }
    }
}

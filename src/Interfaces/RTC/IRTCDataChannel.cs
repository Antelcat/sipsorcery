﻿//-----------------------------------------------------------------------------
// Filename: IRTCDataChannel.cs
//
// Description: Contains the interface definition for the RTCDataChannel
// class as defined by the W3C WebRTC specification. Should be kept up to 
// date with:
// https://www.w3.org/TR/webrtc/#rtcdatachannel
//
// Remarks:
// Specification Soup (as of 23 Mar @021):
//
// - Stream Control Transmission Protocol:
// https://tools.ietf.org/html/rfc4960
//
// - WebRTC Data Channels:
// https://tools.ietf.org/html/rfc8831
//
// - WebRTC Data Channel Establishment Protocol:
// https://tools.ietf.org/html/rfc8832
//
// - Datagram Transport Layer Security (DTLS) Encapsulation of SCTP Packets:
// https://tools.ietf.org/html/rfc8261
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
//
// History:
// 11 Jul 2020	Aaron Clauson	Created, Dublin, Ireland.
// 23 Mar 2021  Aaron Clauson   Refactored for new SCTP implementation.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;

namespace SIPSorcery.Net
{
    public delegate void OnDataChannelMessageDelegate(RTCDataChannel dc, DataChannelPayloadProtocols protocol, byte[] data);

    public enum RTCDataChannelState
    {
        /// <summary>
        /// The user agent is attempting to establish the underlying data transport. 
        /// This is the initial state of an RTCDataChannel object, whether created 
        /// with createDataChannel, or dispatched as a part of an RTCDataChannelEvent.
        /// </summary>
        connecting,

        /// <summary>
        /// The underlying data transport is established and communication is possible.
        /// </summary>
        open,

        /// <summary>
        /// The procedure to close down the underlying data transport has started.
        /// </summary>
        closing,

        /// <summary>
        /// The underlying data transport has been closed or could not be established.
        /// </summary>
        closed
    };

    /// <summary>
    /// The RTCDataChannel interface represents a bi-directional data channel between two peers.
    /// </summary>
    /// <remarks>
    /// Specification https://www.w3.org/TR/webrtc/#webidl-1143016005
    /// </remarks>
    interface IRTCDataChannel
    {
        /// <summary>
        /// The label attribute represents a label that can be used to distinguish this RTCDataChannel 
        /// object from other RTCDataChannel objects. Scripts are allowed to create multiple RTCDataChannel 
        /// objects with the same label. On getting, the attribute MUST return the value of the [[DataChannelLabel]] slot.
        /// </summary>
        string Label { get; }

        /// <summary>
        /// The ordered attribute returns true if the RTCDataChannel is ordered, and false if out of order delivery 
        /// is allowed. On getting, the attribute MUST return the value of the [[Ordered]] slot
        /// </summary>
        bool Ordered { get; }

        /// <summary>
        /// he maxPacketLifeTime attribute returns the length of the time window (in milliseconds) during which 
        /// transmissions and retransmissions may occur in unreliable mode. On getting, the attribute MUST return the 
        /// value of the [[MaxPacketLifeTime]] slot.
        /// </summary>
        ushort? MaxPacketLifeTime { get; }

        /// <summary>
        /// The maxRetransmits attribute returns the maximum number of retransmissions that are attempted in unreliable mode. 
        /// On getting, the attribute MUST return the value of the [[MaxRetransmits]] slot.
        /// </summary>
        ushort? MaxRetransmits { get; }

        /// <summary>
        /// The protocol attribute returns the name of the sub-protocol used with this RTCDataChannel. On getting, the 
        /// attribute MUST return the value of the [[DataChannelProtocol]] slot.
        /// </summary>
        string Protocol { get; }

        /// <summary>
        /// he negotiated attribute returns true if this RTCDataChannel was negotiated by the application, or false otherwise. 
        /// On getting, the attribute MUST return the value of the [[Negotiated]] slot.
        /// </summary>
        bool Negotiated { get; }

        /// <summary>
        /// The id attribute returns the ID for this RTCDataChannel. The value is initially null, which is what will be returned if 
        /// the ID was not provided at channel creation time, and the DTLS role of the SCTP transport has not yet been negotiated. 
        /// Otherwise, it will return the ID that was either selected by the script or generated by the user agent according to 
        /// [RTCWEB-DATA-PROTOCOL]. After the ID is set to a non-null value, it will not change. On getting, the attribute MUST return 
        /// the value of the [[DataChannelId]] slot.
        /// </summary>
        ushort? Id { get; }

        /// <summary>
        /// The readyState attribute represents the state of the RTCDataChannel object. On getting, the attribute MUST return the 
        /// value of the [[ReadyState]] slot.
        /// </summary>
        RTCDataChannelState ReadyState { get; }

        /// <summary>
        /// The bufferedAmount attribute MUST, on getting, return the value of the [[BufferedAmount]] slot. The attribute exposes the 
        /// number of bytes of application data (UTF-8 text and binary data) that have been queued using send(). Even though the data 
        /// transmission can occur in parallel, the returned value MUST NOT be decreased before the current task yielded back to the 
        /// event loop to prevent race conditions. The value does not include framing overhead incurred by the protocol, or buffering 
        /// done by the operating system or network hardware. The value of the [[BufferedAmount]] slot will only increase with each 
        /// call to the send() method as long as the [[ReadyState]] slot is open; however, the slot does not reset to zero once the 
        /// channel closes. When the underlying data transport sends data from its queue, the user agent MUST queue a task that reduces 
        /// [[BufferedAmount]] with the number of bytes that was sent.
        /// </summary>
        ulong BufferedAmount { get; }

        /// <summary>
        /// The bufferedAmountLowThreshold attribute sets the threshold at which the bufferedAmount is considered to be low. When the 
        /// bufferedAmount decreases from above this threshold to equal or below it, the bufferedamountlow event fires. The 
        /// bufferedAmountLowThreshold is initially zero on each new RTCDataChannel, but the application may change its value at any time.
        /// </summary>
        ulong BufferedAmountLowThreshold { get; set; }

        /// <summary>
        /// The RTCDataChannel object's underlying data transport has been established (or re-established).
        /// </summary>
        event Action OnOpen;

        //event Action onbufferedamountlow;
        event Action<string> OnError;
        //event Action onclosing;
        event Action OnClose;
        void close();

        /// <summary>
        /// A message was successfully received.
        /// </summary>
        event OnDataChannelMessageDelegate OnMessage;

        string BinaryType { get; set; }
        void send(string data);
        void send(byte[] data);
    };

    public class RTCDataChannelInit
    {
        public bool? Ordered { get; set; }
        public ushort? MaxPacketLifeTime { get; set; }
        public ushort? MaxRetransmits { get; set; }
        public string? Protocol { get; set; }
        public bool? Negotiated { get; set; }
        public ushort? Id { get; set; }
    };
}

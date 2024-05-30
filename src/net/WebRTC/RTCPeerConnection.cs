//-----------------------------------------------------------------------------
// Filename: RTCPeerConnection.cs
//
// Description: Represents a WebRTC RTCPeerConnection.
//
// Specification Soup (as of 13 Jul 2020):
// - "Session Description Protocol (SDP) Offer/Answer procedures for
//   Interactive Connectivity Establishment(ICE)" [ed: specification for
//   including ICE candidates in SDP]:
//   https://tools.ietf.org/html/rfc8839
// - "Session Description Protocol (SDP) Offer/Answer Procedures For Stream
//   Control Transmission Protocol(SCTP) over Datagram Transport Layer
//   Security(DTLS) Transport." [ed: specification for negotiating
//   data channels in SDP, this defines the SDP "sctp-port" attribute] 
//   https://tools.ietf.org/html/rfc8841
// - "SDP-based Data Channel Negotiation" [ed: not currently implemented,
//   actually seems like a big pain to implement this given it can already
//   be done in-band on the SCTP connection]:
//   https://tools.ietf.org/html/rfc8864
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
//
// History:
// 04 Mar 2016	Aaron Clauson	Created.
// 25 Aug 2019  Aaron Clauson   Updated from video only to audio and video.
// 18 Jan 2020  Aaron Clauson   Combined WebRTCPeer and WebRTCSession.
// 16 Mar 2020  Aaron Clauson   Refactored to support RTCPeerConnection interface.
// 13 Jul 2020  Aaron Clauson   Added data channel support.
// 22 Mar 2021  Aaron Clauson   Refactored data channels logic for new SCTP
//                              implementation.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Tls;
using SIPSorcery.Interfaces;
using SIPSorcery.net.RTP;
using SIPSorcery.SIP.App;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    /// <summary>
    /// Options for creating the SDP offer.
    /// </summary>
    /// <remarks>
    /// As specified in https://www.w3.org/TR/webrtc/#dictionary-rtcofferoptions-members.
    /// </remarks>
    //public class RTCOfferOptions
    //{
    //    /// <summary>
    //    /// If true then a new set of ICE credentials will be generated otherwise any
    //    /// existing set of credentials will be used.
    //    /// </summary>
    //    public bool iceRestart;
    //}

    /// <summary>
    /// Initialiser for the RTCSessionDescription instance.
    /// </summary>
    /// <remarks>
    /// As specified in https://www.w3.org/TR/webrtc/#rtcsessiondescription-class.
    /// </remarks>
    public class RTCSessionDescriptionInit : IJsonify
    {
        /// <summary>
        /// The type of the Session Description.
        /// </summary>
        [JsonPropertyName("type")] public required SdpType Type { get; init; }

        /// <summary>
        /// A string representation of the Session Description.
        /// </summary>
        [JsonPropertyName("sdp")] public required string Sdp { get; init; }
    }

    /// <summary>
    /// Describes a pairing of an RTP sender and receiver and their shared state. The state
    /// is set by and relevant for the SDP that is controlling the RTP.
    /// </summary>
    //public class RTCRtpTransceiver
    //{
    //    /// <summary>
    //    /// The media ID of the SDP m-line associated with this transceiver.
    //    /// </summary>
    //    public string MID { get; private set; }

    //    /// <summary>
    //    /// The current state of the RTP flow between us and the remote party.
    //    /// </summary>
    //    public MediaStreamStatusEnum Direction { get; private set; } = MediaStreamStatusEnum.SendRecv;

    //    public RTCRtpTransceiver(string mid)
    //    {
    //        MID = mid;
    //    }

    //    public void SetStreamStatus(MediaStreamStatusEnum direction)
    //    {
    //        Direction = direction;
    //    }
    //}

    /// <summary>
    /// Represents a WebRTC RTCPeerConnection.
    /// </summary>
    /// <remarks>
    /// Interface is defined in https://www.w3.org/TR/webrtc/#interface-definition.
    /// The Session Description offer/answer mechanisms are detailed in
    /// https://tools.ietf.org/html/rfc8829 "JavaScript Session Establishment Protocol (JSEP)".
    /// </remarks>
    public class RTCPeerConnection : RTPSession, IRTCPeerConnection
    {
        // SDP constants.
        //private new const string RTP_MEDIA_PROFILE = "RTP/SAVP";
        private const string RTP_MEDIA_NON_FEEDBACK_PROFILE = "UDP/TLS/RTP/SAVP";
        private const string RTP_MEDIA_FEEDBACK_PROFILE = "UDP/TLS/RTP/SAVPF";
        private const string RTP_MEDIA_DATACHANNEL_DTLS_PROFILE = "DTLS/SCTP"; // Legacy.
        private const string RTP_MEDIA_DATACHANNEL_UDPDTLS_PROFILE = "UDP/DTLS/SCTP";
        private const string SDP_DATACHANNEL_FORMAT_ID = "webrtc-datachannel";
        private const string RTCP_MUX_ATTRIBUTE = "a=rtcp-mux"; // Indicates the media announcement is using multiplexed RTCP.
        private const string BUNDLE_ATTRIBUTE = "BUNDLE";
        private const string ICE_OPTIONS = "ice2,trickle"; // Supported ICE options.
        private const string NORMAL_CLOSE_REASON = "normal";
        private const ushort SCTP_DEFAULT_PORT = 5000;
        private const string UNKNOWN_DATACHANNEL_ERROR = "unknown";
        public const int RTP_HEADER_EXTENSION_ID_ABS_SEND_TIME = 2;
        public const string RTP_HEADER_EXTENSION_URI_ABS_SEND_TIME = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

        /// <summary>
        /// The period to wait for the SCTP association to complete before giving up.
        /// In theory this should be very quick as the DTLS connection should already have been established
        /// and the SCTP logic only needs to send the small handshake messages to establish
        /// the association.
        /// </summary>
        private const int SCTP_ASSOCIATE_TIMEOUT_SECONDS = 2;

        private new readonly string RTP_MEDIA_PROFILE = RTP_MEDIA_NON_FEEDBACK_PROFILE;
        private readonly string RTCP_ATTRIBUTE = $"a=rtcp:{SDP.IGNORE_RTP_PORT_NUMBER} IN IP4 0.0.0.0";

        public string SessionID { get; private set; }
        public string SdpSessionID { get; private set; }
        public string LocalSdpSessionID { get; private set; }
        public IReadOnlyCollection<RTCDataChannel> DataChannels => dataChannels;

        /// <summary>
        /// The ICE role the peer is acting in.
        /// </summary>
        public IceRolesEnum IceRole { get; set; } = IceRolesEnum.actpass;

        /// <summary>
        /// The DTLS fingerprint supplied by the remote peer in their SDP. Needs to be checked
        /// that the certificate supplied during the DTLS handshake matches.
        /// </summary>
        public RTCDtlsFingerprint RemotePeerDtlsFingerprint { get; private set; }

        public bool IsDtlsNegotiationComplete { get; private set; }

        public RTCSessionDescription? LocalDescription { get; private set; }

        public RTCSessionDescription? RemoteDescription { get; private set; }

        public RTCSessionDescription? CurrentLocalDescription => LocalDescription;

        public RTCSessionDescription? PendingLocalDescription => null;

        public RTCSessionDescription? CurrentRemoteDescription => RemoteDescription;

        public RTCSessionDescription? PendingRemoteDescription => null;

        public RTCSignalingState SignalingState { get; private set; } = RTCSignalingState.Closed;

        public RTCIceGatheringState IceGatheringState => rtpIceChannel.IceGatheringState;

        public RTCIceConnectionState IceConnectionState => rtpIceChannel.IceConnectionState;

        public RTCPeerConnectionState ConnectionState { get; private set; } = RTCPeerConnectionState.New;

        public bool CanTrickleIceCandidates => true;

        private readonly RTCConfiguration configuration;
        private readonly RtpIceChannel rtpIceChannel;
        private readonly RTCDataChannelCollection dataChannels;
        private readonly Task iceGatheringTask;

        private Certificate dtlsCertificate;
        private AsymmetricKeyParameter dtlsPrivateKey;
        private DtlsSrtpTransport dtlsHandle;

        /// <summary>
        /// Local ICE candidates that have been supplied directly by the application.
        /// Useful for cases where the application may has extra information about the
        /// network set up such as 1:1 NATs as used by Azure and AWS.
        /// </summary>
        private readonly List<RTCIceCandidate> applicationIceCandidates = [];

        /// <summary>
        /// The certificate being used to negotiate the DTLS handshake with the 
        /// remote peer.
        /// </summary>
        //private RTCCertificate _currentCertificate;
        //public RTCCertificate CurrentCertificate
        //{
        //    get
        //    {
        //        return _currentCertificate;
        //    }
        //}

        /// <summary>
        /// The fingerprint of the certificate being used to negotiate the DTLS handshake with the 
        /// remote peer.
        /// </summary>
        public RTCDtlsFingerprint DtlsCertificateFingerprint { get; }

        /// <summary>
        /// The SCTP transport over which SCTP data is sent and received.
        /// </summary>
        /// <remarks>
        /// WebRTC API definition:
        /// https://www.w3.org/TR/webrtc/#attributes-15
        /// </remarks>
        public RTCSctpTransport Sctp { get; }

        /// <summary>
        /// Informs the application that session negotiation needs to be done (i.e. a createOffer call 
        /// followed by setLocalDescription).
        /// </summary>
        public event Action? OnNegotiationNeeded;

        /// <summary>
        /// A new ICE candidate is available for the Peer Connection.
        /// </summary>
        public event Action<RTCIceCandidate>? OnIceCandidate
        {
            add
            {
                var notifyIce = onIceCandidate == null && value != null;
                onIceCandidate += value;
                if (notifyIce)
                {
                    foreach (var ice in rtpIceChannel.Candidates)
                    {
                        onIceCandidate?.Invoke(ice);
                    }
                }
            }
            remove => onIceCandidate -= value;
        }
        
        private event Action<RTCIceCandidate>? onIceCandidate;

        private CancellationTokenSource cancellationTokenSource = new();
        private readonly object renegotiationLock = new();
        private volatile bool requireRenegotiation = true;

        public override bool RequireRenegotiation
        {
            get => requireRenegotiation;

            protected internal set
            {
                lock (renegotiationLock)
                {
                    requireRenegotiation = value;
                    // Remove Remote Description
                    if (requireRenegotiation)
                    {
                        base.RemoteDescription = null;
                    }
                }

                // Remove NegotiationTask when state not stable
                if (!requireRenegotiation || SignalingState != RTCSignalingState.Stable)
                {
                    CancelOnNegotiationNeededTask();
                }
                // Call Renegotiation Delayed (We need to wait as user can try add multiple tracks in sequence)
                else
                {
                    StartOnNegotiationNeededTask();
                }
            }
        }

        /// <summary>
        /// A failure occurred when gathering ICE candidates.
        /// </summary>
        public event Action<RTCIceCandidate, string>? OnIceCandidateError;

        /// <summary>
        /// The signaling state has changed. This state change is the result of either setLocalDescription or 
        /// setRemoteDescription being invoked.
        /// </summary>
        public event Action? OnSignalingStateChange;

        /// <summary>
        /// This Peer Connection's ICE connection state has changed.
        /// </summary>
        public event Action<RTCIceConnectionState>? OnIceConnectionStateChange;

        /// <summary>
        /// This Peer Connection's ICE gathering state has changed.
        /// </summary>
        public event Action<RTCIceGatheringState>? OnIceGatheringStateChange;

        /// <summary>
        /// The state of the peer connection. A state of connected means the ICE checks have 
        /// succeeded and the DTLS handshake has completed. Once in the connected state it's
        /// suitable for media packets can be exchanged.
        /// </summary>
        public event Action<RTCPeerConnectionState>? OnConnectionStateChange;

        /// <summary>
        /// Fires when a new data channel is created by the remote peer.
        /// </summary>
        public event Action<RTCDataChannel>? OnDataChannel;

        /// <summary>
        /// Constructor to create a new RTC peer connection instance.
        /// </summary>
        /// <param name="configuration">Optional.</param>
        public RTCPeerConnection(RTCConfiguration? configuration = null, int bindPort = 0, PortRange? portRange = null, bool videoAsPrimary = false) :
            base(true, true, true, configuration?.X_BindAddress, bindPort, portRange)
        {
            dataChannels = new RTCDataChannelCollection(useEvenIds: () => dtlsHandle.IsClient);

            if (this.configuration != null &&
                this.configuration.iceTransportPolicy == RTCIceTransportPolicy.relay &&
                this.configuration.iceServers?.Count == 0)
            {
                throw new ApplicationException("RTCPeerConnection must have at least one ICE server specified for a relay only transport policy.");
            }

            if (configuration != null)
            {
                this.configuration = configuration;

                if (!InitializeCertificates(configuration) && !InitializeCertificates2(configuration))
                {
                    Logger.LogWarning("No DTLS certificate is provided in the configuration");
                }

                if (this.configuration.X_UseRtpFeedbackProfile)
                {
                    RTP_MEDIA_PROFILE = RTP_MEDIA_FEEDBACK_PROFILE;
                }
            }
            else
            {
                this.configuration = new RTCConfiguration();
            }

            if (dtlsCertificate == null)
            {
                // No certificate was provided so create a new self signed one.
                (dtlsCertificate, dtlsPrivateKey) = DtlsUtils.CreateSelfSignedTlsCert();
            }

            DtlsCertificateFingerprint = DtlsUtils.Fingerprint(dtlsCertificate);

            SessionID = Guid.NewGuid().ToString();
            LocalSdpSessionID = Crypto.GetRandomInt(5).ToString();

            // Request the underlying RTP session to create a single RTP channel that will
            // be used to multiplex all required media streams.
            addSingleTrack(videoAsPrimary);

            rtpIceChannel = GetRtpChannel();

            rtpIceChannel.OnIceCandidate += (candidate) => onIceCandidate?.Invoke(candidate);
            rtpIceChannel.OnIceConnectionStateChange += IceConnectionStateChange;
            rtpIceChannel.OnIceGatheringStateChange += (state) => OnIceGatheringStateChange?.Invoke(state);
            rtpIceChannel.OnIceCandidateError += (candidate, error) => OnIceCandidateError?.Invoke(candidate, error);

            OnRtpClosed += Close;
            OnRtcpBye += Close;

            //Cancel Negotiation Task Event to Prevent Duplicated Calls
            OnNegotiationNeeded += CancelOnNegotiationNeededTask;

            Sctp = new RTCSctpTransport(SCTP_DEFAULT_PORT, SCTP_DEFAULT_PORT, rtpIceChannel.RTPPort);

            OnNegotiationNeeded?.Invoke();

            // This is the point the ICE session potentially starts contacting STUN and TURN servers.
            // This job was moved to a background thread as it was observed that interacting with the OS network
            // calls and/or initialising DNS was taking up to 600ms, see
            // https://github.com/sipsorcery-org/sipsorcery/issues/456.
            iceGatheringTask = Task.Run(rtpIceChannel.StartGathering);
        }

        private bool InitializeCertificates(RTCConfiguration configuration)
        {
            if (configuration.certificates == null || configuration.certificates.Count == 0)
            {
                return false;
            }

            // Find the first certificate that has a usable private key.
#pragma warning disable CS0618 // Type or member is obsolete
            RTCCertificate usableCert = null;
#pragma warning restore CS0618 // Type or member is obsolete
            foreach (var cert in this.configuration.certificates)
            {
                // Attempting to check that a certificate has an exportable private key.
                // TODO: Does not seem to be a particularly reliable way of checking private key exportability.
                if (cert.Certificate.HasPrivateKey)
                {
                    //if (cert.Certificate.PrivateKey is RSACryptoServiceProvider)
                    //{
                    //    var rsa = cert.Certificate.PrivateKey as RSACryptoServiceProvider;
                    //    if (!rsa.CspKeyContainerInfo.Exportable)
                    //    {
                    //        logger.LogWarning($"RTCPeerConnection was passed a certificate for {cert.Certificate.FriendlyName} with a non-exportable RSA private key.");
                    //    }
                    //    else
                    //    {
                    //        usableCert = cert;
                    //        break;
                    //    }
                    //}
                    //else
                    //{
                    usableCert = cert;
                    break;
                    //}
                }
            }

            if (usableCert == null)
            {
                throw new ApplicationException(
                    "RTCPeerConnection was not able to find a certificate from the input configuration list with a usable private key.");
            }

            dtlsCertificate = DtlsUtils.LoadCertificateChain(usableCert.Certificate);
            dtlsPrivateKey = DtlsUtils.LoadPrivateKeyResource(usableCert.Certificate);

            return true;
        }

        private bool InitializeCertificates2(RTCConfiguration configuration)
        {
            if (configuration.certificates2 == null || configuration.certificates2.Count == 0)
            {
                return false;
            }

            dtlsCertificate = new Certificate(new[] { configuration.certificates2[0].Certificate.CertificateStructure });
            dtlsPrivateKey = configuration.certificates2[0].PrivateKey;

            return true;
        }

        /// <summary>
        /// Event handler for ICE connection state changes.
        /// </summary>
        /// <param name="iceState">The new ICE connection state.</param>
        private async void IceConnectionStateChange(RTCIceConnectionState iceState)
        {
            OnIceConnectionStateChange?.Invoke(IceConnectionState);

            if (iceState == RTCIceConnectionState.connected && rtpIceChannel.NominatedEntry != null)
            {
                if (dtlsHandle != null)
                {
                    if (base.PrimaryStream.DestinationEndPoint?.Address.Equals(rtpIceChannel.NominatedEntry.RemoteCandidate.DestinationEndPoint
                            .Address) ==
                        false ||
                        base.PrimaryStream.DestinationEndPoint?.Port != rtpIceChannel.NominatedEntry.RemoteCandidate.DestinationEndPoint.Port)
                    {
                        // Already connected and this event is due to change in the nominated remote candidate.
                        var connectedEP = rtpIceChannel.NominatedEntry.RemoteCandidate.DestinationEndPoint;

                        SetGlobalDestination(connectedEP, connectedEP);
                        Logger.LogInformation($"ICE changing connected remote end point to {connectedEP}.");
                    }

                    if (ConnectionState == RTCPeerConnectionState.Disconnected ||
                        ConnectionState == RTCPeerConnectionState.Failed)
                    {
                        // The ICE connection state change is due to a re-connection.
                        ConnectionState = RTCPeerConnectionState.Connected;
                        OnConnectionStateChange?.Invoke(ConnectionState);
                    }
                }
                else
                {
                    ConnectionState = RTCPeerConnectionState.Connecting;
                    OnConnectionStateChange?.Invoke(ConnectionState);

                    var connectedEP = rtpIceChannel.NominatedEntry.RemoteCandidate.DestinationEndPoint;

                    SetGlobalDestination(connectedEP, connectedEP);
                    Logger.LogInformation($"ICE connected to remote end point {connectedEP}.");

                    bool disableDtlsExtendedMasterSecret = configuration != null && configuration.X_DisableExtendedMasterSecretKey;
                    dtlsHandle = new DtlsSrtpTransport(
                        IceRole == IceRolesEnum.active
                            ? new DtlsSrtpClient(dtlsCertificate, dtlsPrivateKey)
                                { ForceUseExtendedMasterSecret = !disableDtlsExtendedMasterSecret }
                            : (IDtlsSrtpPeer)new DtlsSrtpServer(dtlsCertificate, dtlsPrivateKey)
                                { ForceUseExtendedMasterSecret = !disableDtlsExtendedMasterSecret }
                    );

                    dtlsHandle.OnAlert += OnDtlsAlert;

                    Logger.LogDebug($"Starting DLS handshake with role {IceRole}.");

                    try
                    {
                        bool handshakeResult = await Task.Run(() => DoDtlsHandshake(dtlsHandle)).ConfigureAwait(false);

                        ConnectionState = (handshakeResult) ? RTCPeerConnectionState.Connected : ConnectionState = RTCPeerConnectionState.Failed;
                        OnConnectionStateChange?.Invoke(ConnectionState);

                        if (ConnectionState == RTCPeerConnectionState.Connected)
                        {
                            await base.Start().ConfigureAwait(false);
                            await InitialiseSctpTransport().ConfigureAwait(false);
                        }
                    }
                    catch (Exception excp)
                    {
                        Logger.LogWarning(excp, $"RTCPeerConnection DTLS handshake failed. {excp.Message}");

                        //connectionState = RTCPeerConnectionState.failed;
                        //onconnectionstatechange?.Invoke(connectionState);

                        Close("dtls handshake failed");
                    }
                }
            }

            if (IceConnectionState == RTCIceConnectionState.checking)
            {
                // Not sure about this correspondence between the ICE and peer connection states.
                // TODO: Double check spec.
                //connectionState = RTCPeerConnectionState.connecting;
                //onconnectionstatechange?.Invoke(connectionState);
            }
            else if (IceConnectionState == RTCIceConnectionState.disconnected)
            {
                if (ConnectionState == RTCPeerConnectionState.Connected)
                {
                    ConnectionState = RTCPeerConnectionState.Disconnected;
                    OnConnectionStateChange?.Invoke(ConnectionState);
                }
                else
                {
                    ConnectionState = RTCPeerConnectionState.Failed;
                    OnConnectionStateChange?.Invoke(ConnectionState);
                }
            }
            else if (IceConnectionState == RTCIceConnectionState.failed)
            {
                ConnectionState = RTCPeerConnectionState.Failed;
                OnConnectionStateChange?.Invoke(ConnectionState);
            }
        }

        /// <summary>
        /// Creates a new RTP ICE channel (which manages the UDP socket sending and receiving RTP
        /// packets) for use with this session.
        /// </summary>
        /// <returns>A new RTPChannel instance.</returns>
        protected override RTPChannel CreateRtpChannel()
        {
            if (rtpSessionConfig.IsMediaMultiplexed)
            {
                if (MultiplexRtpChannel != null)
                {
                    return MultiplexRtpChannel;
                }
            }

            var rtpIceChannel = new RtpIceChannel(
                configuration?.X_BindAddress,
                RTCIceComponent.rtp,
                configuration?.iceServers,
                configuration != null ? configuration.iceTransportPolicy : RTCIceTransportPolicy.all,
                configuration != null ? configuration.X_ICEIncludeAllInterfaceAddresses : false,
                rtpSessionConfig.BindPort == 0 ? 0 : rtpSessionConfig.BindPort + rtpChannelsCount * 2 + 2,
                rtpSessionConfig.RtpPortRange);

            if (rtpSessionConfig.IsMediaMultiplexed)
            {
                MultiplexRtpChannel = rtpIceChannel;
            }

            rtpIceChannel.OnRTPDataReceived += OnRTPDataReceived;

            // Start the RTP, and if required the Control, socket receivers and the RTCP session.
            rtpIceChannel.Start();

            rtpChannelsCount++;

            return rtpIceChannel;
        }

        /// <summary>
        /// Sets the local SDP.
        /// </summary>
        /// <remarks>
        /// As specified in https://www.w3.org/TR/webrtc/#dom-peerconnection-setlocaldescription.
        /// </remarks>
        /// <param name="init">Optional. The session description to set as 
        /// local description. If not supplied then an offer or answer will be created as required.
        /// </param>
        public Task SetLocalDescription(RTCSessionDescriptionInit init)
        {
            LocalDescription = new RTCSessionDescription { type = init.Type, sdp = SDP.ParseSDPDescription(init.Sdp) };

            if (init.Type == SdpType.Offer)
            {
                rtpIceChannel.IsController = true;
            }

            if (SignalingState == RTCSignalingState.HaveRemoteOffer)
            {
                SignalingState = RTCSignalingState.Stable;
                OnSignalingStateChange?.Invoke();
            }
            else
            {
                SignalingState = RTCSignalingState.HaveLocalOffer;
                OnSignalingStateChange?.Invoke();
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// This set remote description overload is a convenience method for SIP/VoIP callers
        /// instead of WebRTC callers. The method signature better matches what the SIP
        /// user agent is expecting.
        /// TODO: Using two very similar overloads could cause confusion. Possibly
        /// consolidate.
        /// </summary>
        /// <param name="sdpType">Whether the remote SDP is an offer or answer.</param>
        /// <param name="sessionDescription">The SDP from the remote party.</param>
        /// <returns>The result of attempting to set the remote description.</returns>
        public override SetDescriptionResultEnum SetRemoteDescription(SdpType sdpType, SDP sessionDescription)
        {
            RTCSessionDescriptionInit init = new RTCSessionDescriptionInit
            {
                Sdp = sessionDescription.ToString(),
                Type = (sdpType == SdpType.Answer) ? SdpType.Answer : SdpType.Offer
            };

            return SetRemoteDescription(init);
        }

        /// <summary>
        /// Updates the session after receiving the remote SDP.
        /// </summary>
        /// <param name="init">The answer/offer SDP from the remote party.</param>
        public SetDescriptionResultEnum SetRemoteDescription(RTCSessionDescriptionInit init)
        {
            RemoteDescription = new RTCSessionDescription { type = init.Type, sdp = SDP.ParseSDPDescription(init.Sdp) };

            SDP remoteSdp = RemoteDescription.sdp; // SDP.ParseSDPDescription(init.sdp);

            SdpType sdpType = init.Type == SdpType.Offer ? SdpType.Offer : SdpType.Answer;

            switch (SignalingState)
            {
                case var sigState when sigState == RTCSignalingState.HaveLocalOffer && sdpType == SdpType.Offer:
                    Logger.LogWarning($"RTCPeerConnection received an SDP offer but was already in {sigState} state. Remote offer rejected.");
                    return SetDescriptionResultEnum.WrongSdpTypeOfferAfterOffer;
            }

            var setResult = base.SetRemoteDescription(sdpType, remoteSdp);

            if (setResult == SetDescriptionResultEnum.Ok)
            {
                string remoteIceUser = remoteSdp.IceUfrag;
                string remoteIcePassword = remoteSdp.IcePwd;
                string dtlsFingerprint = remoteSdp.DtlsFingerprint;
                IceRolesEnum? remoteIceRole = remoteSdp.IceRole;

                foreach (var ann in remoteSdp.Media)
                {
                    if (remoteIceUser == null || remoteIcePassword == null || dtlsFingerprint == null || remoteIceRole == null)
                    {
                        remoteIceUser = remoteIceUser ?? ann.IceUfrag;
                        remoteIcePassword = remoteIcePassword ?? ann.IcePwd;
                        dtlsFingerprint = dtlsFingerprint ?? ann.DtlsFingerprint;
                        remoteIceRole = remoteIceRole ?? ann.IceRole;
                    }

                    // Check for data channel announcements.
                    if (ann.Media == SDPMediaTypesEnum.application &&
                        ann.MediaFormats.Count() == 1 &&
                        ann.ApplicationMediaFormats.Single().Key == SDP_DATACHANNEL_FORMAT_ID)
                    {
                        if (ann.Transport == RTP_MEDIA_DATACHANNEL_DTLS_PROFILE ||
                            ann.Transport == RTP_MEDIA_DATACHANNEL_UDPDTLS_PROFILE)
                        {
                            dtlsFingerprint = dtlsFingerprint ?? ann.DtlsFingerprint;
                            remoteIceRole = remoteIceRole ?? remoteSdp.IceRole;
                        }
                        else
                        {
                            Logger.LogWarning($"The remote SDP requested an unsupported data channel transport of {ann.Transport}.");
                            return SetDescriptionResultEnum.DataChannelTransportNotSupported;
                        }
                    }
                }

                SdpSessionID = remoteSdp.SessionId;

                if (remoteSdp.IceImplementation == IceImplementationEnum.lite)
                {
                    rtpIceChannel.IsController = true;
                }
                if (init.Type == SdpType.Answer)
                {
                    rtpIceChannel.IsController = true;
                    IceRole = remoteIceRole == IceRolesEnum.passive ? IceRolesEnum.active : IceRolesEnum.passive;
                }
                //As Chrome does not support changing IceRole while renegotiating we need to keep same previous IceRole if we already negotiated before
                else
                {
                    // Set DTLS role as client.
                    IceRole = IceRolesEnum.active;
                }

                if (remoteIceUser != null && remoteIcePassword != null)
                {
                    rtpIceChannel.SetRemoteCredentials(remoteIceUser, remoteIcePassword);
                }

                if (!string.IsNullOrWhiteSpace(dtlsFingerprint))
                {
                    dtlsFingerprint = dtlsFingerprint.Trim().ToLower();
                    if (RTCDtlsFingerprint.TryParse(dtlsFingerprint, out var remoteFingerprint))
                    {
                        RemotePeerDtlsFingerprint = remoteFingerprint;
                    }
                    else
                    {
                        Logger.LogWarning($"The DTLS fingerprint was invalid or not supported.");
                        return SetDescriptionResultEnum.DtlsFingerprintDigestNotSupported;
                    }
                }
                else
                {
                    Logger.LogWarning("The DTLS fingerprint was missing from the remote party's session description.");
                    return SetDescriptionResultEnum.DtlsFingerprintMissing;
                }

                // All browsers seem to have gone to trickling ICE candidates now but just
                // in case one or more are given we can start the STUN dance immediately.
                if (remoteSdp.IceCandidates != null)
                {
                    foreach (var iceCandidate in remoteSdp.IceCandidates)
                    {
                        AddIceCandidate(new RTCIceCandidateInit { candidate = iceCandidate });
                    }
                }


                ResetRemoteSDPSsrcAttributes();
                foreach (var media in remoteSdp.Media)
                {
                    if (media.IceCandidates != null)
                    {
                        foreach (var iceCandidate in media.IceCandidates)
                        {
                            AddIceCandidate(new RTCIceCandidateInit { candidate = iceCandidate });
                        }
                    }

                    AddRemoteSDPSsrcAttributes(media.Media, media.SsrcAttributes);
                }
                Logger.LogDebug($"SDP:[{remoteSdp}]");
                LogRemoteSDPSsrcAttributes();


                UpdatedSctpDestinationPort();

                if (init.Type == SdpType.Offer)
                {
                    SignalingState = RTCSignalingState.HaveRemoteOffer;
                    OnSignalingStateChange?.Invoke();
                }
                else
                {
                    SignalingState = RTCSignalingState.Stable;
                    OnSignalingStateChange?.Invoke();
                }

                // Trigger the ICE candidate events for any non-host candidates, host candidates are always included in the
                // SDP offer/answer. The reason for the trigger is that ICE candidates cannot be sent to the remote peer
                // until it is ready to receive them which is indicated by the remote offer being received.
                foreach (var nonHostCand in rtpIceChannel.Candidates.Where(x => x.type != RTCIceCandidateType.host))
                {
                    onIceCandidate?.Invoke(nonHostCand);
                }
            }

            return setResult;
        }

        /// <summary>
        /// Close the session including the underlying RTP session and channels.
        /// </summary>
        /// <param name="reason">An optional descriptive reason for the closure.</param>
        public override void Close(string reason)
        {
            if (!IsClosed)
            {
                Logger.LogDebug($"Peer connection closed with reason {(reason != null ? reason : "<none>")}.");

                // Close all DataChannels
                if (DataChannels?.Count > 0)
                {
                    foreach (var dc in DataChannels)
                    {
                        dc?.close();
                    }
                }

                rtpIceChannel?.Close();
                dtlsHandle?.Close();

                Sctp?.Close();

                base.Close(reason); // Here Audio and/or Video Streams are closed

                ConnectionState = RTCPeerConnectionState.Closed;
                OnConnectionStateChange?.Invoke(RTCPeerConnectionState.Closed);
            }
        }

        /// <summary>
        /// Closes the connection with the default reason.
        /// </summary>
        public void Close()
        {
            Close(NORMAL_CLOSE_REASON);
        }

        /// <summary>
        /// Generates the SDP for an offer that can be made to a remote peer.
        /// </summary>
        /// <remarks>
        /// As specified in https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-createoffer.
        /// </remarks>
        /// <param name="options">Optional. If supplied the options will be sued to apply additional
        /// controls over the generated offer SDP.</param>
        public RTCSessionDescriptionInit CreateOffer(RTCOfferOptions options = null)
        {
            List<MediaStream> mediaStreamList = GetMediaStreams();
            //Revert to DefaultStreamStatus
            foreach (var mediaStream in mediaStreamList)
            {
                if (mediaStream.LocalTrack != null && mediaStream.LocalTrack.StreamStatus == MediaStreamStatusEnum.Inactive)
                {
                    mediaStream.LocalTrack.StreamStatus = mediaStream.LocalTrack.DefaultStreamStatus;
                }
            }

            bool excludeIceCandidates = options != null && options.X_ExcludeIceCandidates;
            var offerSdp = createBaseSdp(mediaStreamList, excludeIceCandidates);

            foreach (var mediaStream in offerSdp.Media)
            {
                // when creating offer, tell that we support abs-send-time
                mediaStream.HeaderExtensions.Add(
                    RTP_HEADER_EXTENSION_ID_ABS_SEND_TIME,
                    new RTPHeaderExtension(
                        RTP_HEADER_EXTENSION_ID_ABS_SEND_TIME,
                        RTP_HEADER_EXTENSION_URI_ABS_SEND_TIME));
            }

            foreach (var ann in offerSdp.Media)
            {
                ann.IceRole = IceRole;
            }

            var initDescription = new RTCSessionDescriptionInit
            {
                Type = SdpType.Offer,
                Sdp = offerSdp.ToString()
            };

            return initDescription;
        }

        /// <summary>
        /// Convenience overload to suit SIP/VoIP callers.
        /// TODO: Consolidate with createAnswer.
        /// </summary>
        /// <param name="connectionAddress">Not used.</param>
        /// <returns>An SDP payload to answer an offer from the remote party.</returns>
        public override SDP CreateOffer(IPAddress connectionAddress)
        {
            var result = CreateOffer(null);

            if (result?.Sdp != null)
            {
                return SDP.ParseSDPDescription(result.Sdp);
            }

            return null;
        }

        /// <summary>
        /// Convenience overload to suit SIP/VoIP callers.
        /// TODO: Consolidate with createAnswer.
        /// </summary>
        /// <param name="connectionAddress">Not used.</param>
        /// <returns>An SDP payload to answer an offer from the remote party.</returns>
        public override SDP CreateAnswer(IPAddress connectionAddress)
        {
            var result = CreateAnswer(null);

            if (result?.Sdp != null)
            {
                return SDP.ParseSDPDescription(result.Sdp);
            }

            return null;
        }

        /// <summary>
        /// Creates an answer to an SDP offer from a remote peer.
        /// </summary>
        /// <remarks>
        /// As specified in https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-createanswer and
        /// https://tools.ietf.org/html/rfc3264#section-6.1.
        /// </remarks>
        /// <param name="options">Optional. If supplied the options will be used to apply additional
        /// controls over the generated answer SDP.</param>
        public RTCSessionDescriptionInit CreateAnswer(RTCAnswerOptions? options = null)
        {
            if (RemoteDescription == null)
            {
                throw new ApplicationException("The remote SDP must be set before an SDP answer can be created.");
            }
            else
            {
                List<MediaStream> mediaStreamList = GetMediaStreams();
                //Revert to DefaultStreamStatus
                foreach (var mediaStream in mediaStreamList)
                {
                    if (mediaStream.LocalTrack != null && mediaStream.LocalTrack.StreamStatus == MediaStreamStatusEnum.Inactive)
                    {
                        mediaStream.LocalTrack.StreamStatus = mediaStream.LocalTrack.DefaultStreamStatus;
                    }
                }

                bool excludeIceCandidates = options != null && options.X_ExcludeIceCandidates;
                var answerSdp = createBaseSdp(mediaStreamList, excludeIceCandidates);

                foreach (var media in answerSdp.Media)
                {
                    var remoteMedia = RemoteDescription.sdp.Media.FirstOrDefault(m => m.MediaID == media.MediaID);
                    // when creating answer, copy abs-send-time ext only if the media in offer contained it
                    if (remoteMedia != null)
                    {
                        foreach (var kv in
                                 remoteMedia.HeaderExtensions.Where(kv =>
                                     kv.Value.Uri == RTP_HEADER_EXTENSION_URI_ABS_SEND_TIME))
                        {
                            media.HeaderExtensions.Add(kv.Key, kv.Value);
                        }
                    }
                }

                //if (answerSdp.Media.Any(x => x.Media == SDPMediaTypesEnum.audio))
                //{
                //    var audioAnnouncement = answerSdp.Media.Where(x => x.Media == SDPMediaTypesEnum.audio).Single();
                //    audioAnnouncement.IceRole = IceRole;
                //}

                //if (answerSdp.Media.Any(x => x.Media == SDPMediaTypesEnum.video))
                //{
                //    var videoAnnouncement = answerSdp.Media.Where(x => x.Media == SDPMediaTypesEnum.video).Single();
                //    videoAnnouncement.IceRole = IceRole;
                //}

                RTCSessionDescriptionInit initDescription = new RTCSessionDescriptionInit
                {
                    Type = SdpType.Answer,
                    Sdp = answerSdp.ToString()
                };

                return initDescription;
            }
        }

        /// <summary>
        /// For standard use this method should not need to be called. The remote peer's ICE
        /// user and password will be set when from the SDP. This method is provided for 
        /// diagnostics purposes.
        /// </summary>
        /// <param name="remoteIceUser">The remote peer's ICE user value.</param>
        /// <param name="remoteIcePassword">The remote peer's ICE password value.</param>
        public void SetRemoteCredentials(string remoteIceUser, string remoteIcePassword)
        {
            rtpIceChannel.SetRemoteCredentials(remoteIceUser, remoteIcePassword);
        }

        /// <summary>
        /// Gets the RTP channel being used to send and receive data on this peer connection.
        /// Unlike the base RTP session peer connections only ever use a single RTP channel.
        /// Audio and video (and RTCP) are all multiplexed on the same channel.
        /// </summary>
        public RtpIceChannel GetRtpChannel()
        {
            return PrimaryStream.GetRTPChannel() as RtpIceChannel;
        }

        /// <summary>
        /// Generates the base SDP for an offer or answer. The SDP will then be tailored depending
        /// on whether it's being used in an offer or an answer.
        /// </summary>
        /// <param name="mediaStreamList">THe media streamss to add to the SDP description.</param>
        /// <param name="excludeIceCandidates">If true it indicates the caller does not want ICE candidates added
        /// to the SDP.</param>
        /// <remarks>
        /// From https://tools.ietf.org/html/draft-ietf-mmusic-ice-sip-sdp-39#section-4.2.5:
        ///   "The transport address from the peer for the default destination
        ///   is set to IPv4/IPv6 address values "0.0.0.0"/"::" and port value
        ///   of "9".  This MUST NOT be considered as a ICE failure by the peer
        ///   agent and the ICE processing MUST continue as usual."
        /// </remarks>
        private SDP createBaseSdp(List<MediaStream> mediaStreamList, bool excludeIceCandidates = false)
        {
            // Make sure the ICE gathering of local IP addresses is complete.
            // This task should complete very quickly (<1s) but it is deemed very useful to wait
            // for it to complete as it allows local ICE candidates to be included in the SDP.
            // In theory it would be better to an async/await but that would result in a breaking
            // change to the API and for a one off (once per class instance not once per method call)
            // delay of a few hundred milliseconds it was decided not to break the API.
            iceGatheringTask.Wait();

            SDP offerSdp = new SDP(IPAddress.Loopback);
            offerSdp.SessionId = LocalSdpSessionID;

            string dtlsFingerprint = this.DtlsCertificateFingerprint.ToString();
            bool iceCandidatesAdded = false;


            // Local function to add ICE candidates to one of the media announcements.
            void AddIceCandidates(SDPMediaAnnouncement announcement)
            {
                if (rtpIceChannel.Candidates?.Count > 0)
                {
                    announcement.IceCandidates = new List<string>();

                    // Add ICE candidates.
                    foreach (var iceCandidate in rtpIceChannel.Candidates)
                    {
                        announcement.IceCandidates.Add(iceCandidate.ToString());
                    }

                    foreach (var iceCandidate in applicationIceCandidates)
                    {
                        announcement.IceCandidates.Add(iceCandidate.ToString());
                    }

                    if (rtpIceChannel.IceGatheringState == RTCIceGatheringState.complete)
                    {
                        announcement.AddExtra($"a={SDP.END_ICE_CANDIDATES_ATTRIBUTE}");
                    }
                }
            }

            ;

            // Media announcements must be in the same order in the offer and answer.
            int mediaIndex = 0;
            int audioMediaIndex = 0;
            int videoMediaIndex = 0;
            foreach (var mediaStream in mediaStreamList)
            {
                int mindex = 0;
                string midTag = "0";

                if (base.RemoteDescription == null)
                {
                    mindex = mediaIndex;
                    midTag = mediaIndex.ToString();
                }
                else
                {
                    if (mediaStream.LocalTrack.Kind == SDPMediaTypesEnum.audio)
                    {
                        (mindex, midTag) = base.RemoteDescription.GetIndexForMediaType(mediaStream.LocalTrack.Kind, audioMediaIndex);
                        audioMediaIndex++;
                    }
                    else if (mediaStream.LocalTrack.Kind == SDPMediaTypesEnum.video)
                    {
                        (mindex, midTag) = base.RemoteDescription.GetIndexForMediaType(mediaStream.LocalTrack.Kind, videoMediaIndex);
                        videoMediaIndex++;
                    }
                }
                mediaIndex++;

                if (mindex == SDP.MEDIA_INDEX_NOT_PRESENT)
                {
                    Logger.LogWarning($"Media announcement for {mediaStream.LocalTrack.Kind} omitted due to no reciprocal remote announcement.");
                }
                else
                {
                    SDPMediaAnnouncement announcement = new SDPMediaAnnouncement(
                        mediaStream.LocalTrack.Kind,
                        SDP.IGNORE_RTP_PORT_NUMBER,
                        mediaStream.LocalTrack.Capabilities);

                    announcement.Transport = RTP_MEDIA_PROFILE;
                    announcement.Connection = new SDPConnectionInformation(IPAddress.Any);
                    announcement.AddExtra(RTCP_MUX_ATTRIBUTE);
                    announcement.AddExtra(RTCP_ATTRIBUTE);
                    announcement.MediaStreamStatus = mediaStream.LocalTrack.StreamStatus;
                    announcement.MediaID = midTag;
                    announcement.MLineIndex = mindex;

                    announcement.IceUfrag = rtpIceChannel.LocalIceUser;
                    announcement.IcePwd = rtpIceChannel.LocalIcePassword;
                    announcement.IceOptions = ICE_OPTIONS;
                    announcement.IceRole = IceRole;
                    announcement.DtlsFingerprint = dtlsFingerprint;

                    if (iceCandidatesAdded == false && !excludeIceCandidates)
                    {
                        AddIceCandidates(announcement);
                        iceCandidatesAdded = true;
                    }

                    if (mediaStream.LocalTrack.Ssrc != 0)
                    {
                        string trackCname = mediaStream.RtcpSession?.Cname;

                        if (trackCname != null)
                        {
                            announcement.SsrcAttributes.Add(new SDPSsrcAttribute(mediaStream.LocalTrack.Ssrc, trackCname, null));
                        }
                    }

                    offerSdp.Media.Add(announcement);
                }
            }

            if (DataChannels.Count > 0 || (base.RemoteDescription?.Media.Any(x => x.Media == SDPMediaTypesEnum.application) ?? false))
            {
                (int mindex, string midTag) = base.RemoteDescription == null
                    ? (mediaIndex, mediaIndex.ToString())
                    : base.RemoteDescription.GetIndexForMediaType(SDPMediaTypesEnum.application, 0);
                mediaIndex++;

                if (mindex == SDP.MEDIA_INDEX_NOT_PRESENT)
                {
                    Logger.LogWarning($"Media announcement for data channel establishment omitted due to no reciprocal remote announcement.");
                }
                else
                {
                    SDPMediaAnnouncement dataChannelAnnouncement = new SDPMediaAnnouncement(
                        SDPMediaTypesEnum.application,
                        SDP.IGNORE_RTP_PORT_NUMBER,
                        new List<SDPApplicationMediaFormat> { new SDPApplicationMediaFormat(SDP_DATACHANNEL_FORMAT_ID) });
                    dataChannelAnnouncement.Transport = RTP_MEDIA_DATACHANNEL_UDPDTLS_PROFILE;
                    dataChannelAnnouncement.Connection = new SDPConnectionInformation(IPAddress.Any);

                    dataChannelAnnouncement.SctpPort = SCTP_DEFAULT_PORT;
                    dataChannelAnnouncement.MaxMessageSize = Sctp.MaxMessageSize;
                    dataChannelAnnouncement.MLineIndex = mindex;
                    dataChannelAnnouncement.MediaID = midTag;
                    dataChannelAnnouncement.IceUfrag = rtpIceChannel.LocalIceUser;
                    dataChannelAnnouncement.IcePwd = rtpIceChannel.LocalIcePassword;
                    dataChannelAnnouncement.IceOptions = ICE_OPTIONS;
                    dataChannelAnnouncement.IceRole = IceRole;
                    dataChannelAnnouncement.DtlsFingerprint = dtlsFingerprint;

                    if (iceCandidatesAdded == false && !excludeIceCandidates)
                    {
                        AddIceCandidates(dataChannelAnnouncement);
                        iceCandidatesAdded = true;
                    }

                    offerSdp.Media.Add(dataChannelAnnouncement);
                }
            }

            // Set the Bundle attribute to indicate all media announcements are being multiplexed.
            if (offerSdp.Media?.Count > 0)
            {
                offerSdp.Group = BUNDLE_ATTRIBUTE;
                foreach (var ann in offerSdp.Media.OrderBy(x => x.MLineIndex).ThenBy(x => x.MediaID))
                {
                    offerSdp.Group += $" {ann.MediaID}";
                }
            }

            return offerSdp;
        }

        /// <summary>
        /// From RFC5764: <![CDATA[
        ///             +----------------+
        ///             | 127 < B< 192  -+--> forward to RTP
        ///             |                |
        /// packet -->  |  19 < B< 64   -+--> forward to DTLS
        ///             |                |
        ///             |       B< 2    -+--> forward to STUN
        ///             +----------------+
        /// ]]>
        /// </summary>
        /// <paramref name="localPort">The local port on the RTP socket that received the packet.</paramref>
        /// <param name="remoteEP">The remote end point the packet was received from.</param>
        /// <param name="buffer">The data received.</param>
        private void OnRTPDataReceived(int localPort, IPEndPoint? remoteEP, byte[] buffer)
        {
            //logger.LogDebug($"RTP channel received a packet from {remoteEP}, {buffer?.Length} bytes.");

            // By this point the RTP ICE channel has already processed any STUN packets which means 
            // it's only necessary to separate RTP/RTCP from DTLS.
            // Because DTLS packets can be fragmented and RTP/RTCP should never be use the RTP/RTCP 
            // prefix to distinguish.

            if (buffer?.Length > 0)
            {
                try
                {
                    if (buffer?.Length > RTPHeader.MIN_HEADER_LEN && buffer[0] >= 128 && buffer[0] <= 191)
                    {
                        // RTP/RTCP packet.
                        base.OnReceive(localPort, remoteEP, buffer);
                    }
                    else
                    {
                        if (dtlsHandle != null)
                        {
                            //logger.LogDebug($"DTLS transport received {buffer.Length} bytes from {AudioDestinationEndPoint}.");
                            dtlsHandle.WriteToRecvStream(buffer);
                        }
                        else
                        {
                            Logger.LogWarning($"DTLS packet received {buffer.Length} bytes from {remoteEP} but no DTLS transport available.");
                        }
                    }
                }
                catch (Exception excp)
                {
                    Logger.LogError($"Exception RTCPeerConnection.OnRTPDataReceived {excp.Message}");
                }
            }
        }

        /// <summary>
        /// Used to add a local ICE candidate. These are for candidates that the application may
        /// want to provide in addition to the ones that will be automatically determined. An
        /// example is when a machine is behind a 1:1 NAT and the application wants a host 
        /// candidate with the public IP address to be included.
        /// </summary>
        /// <param name="candidate">The ICE candidate to add.</param>
        /// <example>
        /// var natCandidate = new RTCIceCandidate(RTCIceProtocol.udp, natAddress, natPort, RTCIceCandidateType.host);
        /// pc.addLocalIceCandidate(natCandidate);
        /// </example>
        public void addLocalIceCandidate(RTCIceCandidate candidate)
        {
            candidate.usernameFragment = rtpIceChannel.LocalIceUser;
            applicationIceCandidates.Add(candidate);
        }

        /// <summary>
        /// Used to add remote ICE candidates to the peer connection's checklist.
        /// </summary>
        /// <param name="candidateInit">The remote ICE candidate to add.</param>
        public void AddIceCandidate(RTCIceCandidateInit candidateInit)
        {
            RTCIceCandidate candidate = new RTCIceCandidate(candidateInit);

            if (rtpIceChannel.Component == candidate.component)
            {
                rtpIceChannel.AddRemoteCandidate(candidate);
            }
            else
            {
                Logger.LogWarning($"Remote ICE candidate not added as no available ICE session for component {candidate.component}.");
            }
        }

        /// <summary>
        /// Restarts the ICE session gathering and connection checks.
        /// </summary>
        public void RestartIce()
        {
            rtpIceChannel.Restart();
        }

        /// <summary>
        /// Gets the initial optional configuration settings this peer connection was created
        /// with.
        /// </summary>
        /// <returns>If available the initial configuration options.</returns>
        public RTCConfiguration GetConfiguration()
        {
            return configuration;
        }

        /// <summary>
        /// Not implemented. Configuration options cannot currently be changed once the peer
        /// connection has been initialised.
        /// </summary>
        public void SetConfiguration(RTCConfiguration configuration = null)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Once the SDP exchange has been made the SCTP transport ports are known. If the destination
        /// port is not using the default value attempt to update it on teh SCTP transprot.
        /// </summary>
        private void UpdatedSctpDestinationPort()
        {
            // If a data channel was requested by the application then create the SCTP association.
            var sctpAnn = base.RemoteDescription.Media.Where(x => x.Media == SDPMediaTypesEnum.application).FirstOrDefault();
            ushort destinationPort = sctpAnn?.SctpPort != null ? sctpAnn.SctpPort.Value : SCTP_DEFAULT_PORT;

            if (destinationPort != SCTP_DEFAULT_PORT)
            {
                Sctp.UpdateDestinationPort(destinationPort);
            }
        }

        /// <summary>
        /// These internal function is used to call Renegotiation Event with delay as the user should call addTrack/removeTrack in sequence so we need a small delay to prevent multiple renegotiation calls
        /// </summary>
        /// <returns>Current Executing Task</returns>
        protected virtual Task StartOnNegotiationNeededTask()
        {
            const int RENEGOTIATION_CALL_DELAY = 100;

            //We need to reset the timer every time that we call this function
            CancelOnNegotiationNeededTask();

            CancellationToken token;
            lock (renegotiationLock)
            {
                cancellationTokenSource = new CancellationTokenSource();
                token = cancellationTokenSource.Token;
            }
            return Task.Run(async () =>
                {
                    //Call Renegotiation Delayed
                    await Task.Delay(RENEGOTIATION_CALL_DELAY, token);

                    //Prevent continue with cancellation requested
                    if (token.IsCancellationRequested)
                    {
                        return;
                    }
                    else
                    {
                        if (requireRenegotiation)
                        {
                            //We Already Subscribe CancelRenegotiationEventTask in Constructor so we dont need to handle with this function again here
                            OnNegotiationNeeded?.Invoke();
                        }
                    }
                },
                token);
        }

        /// <summary>
        /// Cancel current Negotiation Event Call to prevent running thread to call OnNegotiationNeeded
        /// </summary>
        protected virtual void CancelOnNegotiationNeededTask()
        {
            lock (renegotiationLock)
            {
                if (cancellationTokenSource != null)
                {
                    if (!cancellationTokenSource.IsCancellationRequested)
                    {
                        cancellationTokenSource.Cancel();
                    }

                    cancellationTokenSource = null;
                }
            }
        }

        /// <summary>
        /// Initialises the SCTP transport. This will result in the DTLS SCTP transport listening 
        /// for incoming INIT packets if the remote peer attempts to create the association. The local
        /// peer will NOT attempt to establish the association at this point. It's up to the
        /// application to specify it wants a data channel to initiate the SCTP association attempt.
        /// </summary>
        private async Task InitialiseSctpTransport()
        {
            try
            {
                Sctp.OnStateChanged += OnSctpTransportStateChanged;
                Sctp.Start(dtlsHandle.Transport, dtlsHandle.IsClient);

                if (DataChannels.Count > 0)
                {
                    await InitialiseSctpAssociation().ConfigureAwait(false);
                }
            }
            catch (Exception excp)
            {
                Logger.LogError($"SCTP exception establishing association, data channels will not be available. {excp}");
                Sctp?.Close();
            }
        }

        /// <summary>
        /// Event handler for changes to the SCTP transport state.
        /// </summary>
        /// <param name="state">The new transport state.</param>
        private void OnSctpTransportStateChanged(RTCSctpTransportState state)
        {
            if (state == RTCSctpTransportState.Connected)
            {
                Logger.LogDebug("SCTP transport successfully connected.");

                Sctp.RTCSctpAssociation.OnDataChannelData += OnSctpAssociationDataChunk;
                Sctp.RTCSctpAssociation.OnDataChannelOpened += OnSctpAssociationDataChannelOpened;
                Sctp.RTCSctpAssociation.OnNewDataChannel += OnSctpAssociationNewDataChannel;

                // Create new SCTP streams for any outstanding data channel requests.
                foreach (var dataChannel in dataChannels.ActivatePendingChannels())
                {
                    OpenDataChannel(dataChannel);
                }
            }
        }

        /// <summary>
        /// Event handler for a new data channel being opened by the remote peer.
        /// </summary>
        private void OnSctpAssociationNewDataChannel(
            ushort streamID,
            DataChannelTypes type,
            ushort priority,
            uint reliability,
            string label,
            string protocol)
        {
            Logger.LogInformation($"WebRTC new data channel opened by remote peer for stream ID {streamID}, type {type}, " +
                                  $"priority {priority}, reliability {reliability}, label {label}, protocol {protocol}.");

            // TODO: Set reliability, priority etc. properties on the data channel.
            var dc = new RTCDataChannel(Sctp) { Id = streamID, Label = label, IsOpened = true, ReadyState = RTCDataChannelState.open };

            dc.SendDcepAck();

            if (dataChannels.AddActiveChannel(dc))
            {
                OnDataChannel?.Invoke(dc);
            }
            else
            {
                // TODO: What's the correct behaviour here?? I guess use the newest one and remove the old one?
                Logger.LogWarning($"WebRTC duplicate data channel requested for stream ID {streamID}.");
            }
        }

        /// <summary>
        /// Event handler for the confirmation that a data channel opened by this peer has been acknowledged.
        /// </summary>
        /// <param name="streamID">The ID of the stream corresponding to the acknowledged data channel.</param>
        private void OnSctpAssociationDataChannelOpened(ushort streamID)
        {
            dataChannels.TryGetChannel(streamID, out var dc);

            string label = dc != null ? dc.Label : "<none>";
            Logger.LogInformation($"WebRTC data channel opened label {label} and stream ID {streamID}.");

            if (dc != null)
            {
                dc.GotAck();
            }
            else
            {
                Logger.LogWarning($"WebRTC data channel got ACK but data channel not found for stream ID {streamID}.");
            }
        }

        /// <summary>
        /// Event handler for an SCTP DATA chunk being received on the SCTP association.
        /// </summary>
        private void OnSctpAssociationDataChunk(SctpDataFrame frame)
        {
            if (dataChannels.TryGetChannel(frame.StreamID, out var dc))
            {
                dc.GotData(frame.StreamID, frame.StreamSeqNum, frame.PPID, frame.UserData);
            }
            else
            {
                Logger.LogWarning($"WebRTC data channel got data but no channel found for stream ID {frame.StreamID}.");
            }
        }

        /// <summary>
        /// When a data channel is requested an SCTP association is needed. This method attempts to 
        /// initialise the association if it is not already available.
        /// </summary>
        private async Task InitialiseSctpAssociation()
        {
            if (Sctp.RTCSctpAssociation.State != SctpAssociationState.Established)
            {
                Sctp.Associate();
            }

            if (Sctp.State != RTCSctpTransportState.Connected)
            {
                TaskCompletionSource<bool> onSctpConnectedTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                Sctp.OnStateChanged += (state) =>
                {
                    Logger.LogDebug($"SCTP transport for create data channel request changed to state {state}.");

                    if (state == RTCSctpTransportState.Connected)
                    {
                        onSctpConnectedTcs.TrySetResult(true);
                    }
                };

                DateTime startTime = DateTime.Now;

                var completedTask = await Task.WhenAny(onSctpConnectedTcs.Task, Task.Delay(SCTP_ASSOCIATE_TIMEOUT_SECONDS * 1000))
                    .ConfigureAwait(false);

                if (Sctp.State != RTCSctpTransportState.Connected)
                {
                    var duration = DateTime.Now.Subtract(startTime).TotalMilliseconds;

                    if (completedTask != onSctpConnectedTcs.Task)
                    {
                        throw new ApplicationException(
                            $"SCTP association timed out after {duration:0.##}ms with association in state {Sctp.RTCSctpAssociation.State} when attempting to create a data channel.");
                    }
                    else
                    {
                        throw new ApplicationException(
                            $"SCTP association failed after {duration:0.##}ms with association in state {Sctp.RTCSctpAssociation.State} when attempting to create a data channel.");
                    }
                }
            }
        }

        /// <summary>
        /// Adds a new data channel to the peer connection.
        /// </summary>
        /// <remarks>
        /// WebRTC API definition:
        /// https://www.w3.org/TR/webrtc/#methods-11
        /// </remarks>
        /// <param name="label">The label used to identify the data channel.</param>
        /// <returns>The data channel created.</returns>
        public async Task<RTCDataChannel> createDataChannel(string label, RTCDataChannelInit? init = null)
        {
            Logger.LogDebug($"Data channel create request for label {label}.");

            RTCDataChannel channel = new RTCDataChannel(Sctp, init)
            {
                Label = label,
            };

            if (ConnectionState == RTCPeerConnectionState.Connected)
            {
                // If the peer connection is not in a connected state there's no point doing anything
                // with the SCTP transport. If the peer connection does connect then a check will
                // be made for any pending data channels and the SCTP operations will be done then.

                if (Sctp == null || Sctp.State != RTCSctpTransportState.Connected)
                {
                    throw new ApplicationException("No SCTP transport is available.");
                }
                else
                {
                    if (Sctp.RTCSctpAssociation == null ||
                        Sctp.RTCSctpAssociation.State != SctpAssociationState.Established)
                    {
                        await InitialiseSctpAssociation().ConfigureAwait(false);
                    }

                    dataChannels.AddActiveChannel(channel);
                    OpenDataChannel(channel);

                    // Wait for the DCEP ACK from the remote peer.
                    TaskCompletionSource<string> isopen = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                    channel.OnOpen += () => isopen.TrySetResult(string.Empty);
                    channel.OnError += (err) => isopen.TrySetResult(err);
                    var error = await isopen.Task.ConfigureAwait(false);

                    if (error != string.Empty)
                    {
                        throw new ApplicationException($"Data channel creation failed with: {error}");
                    }
                    else
                    {
                        return channel;
                    }
                }
            }
            else
            {
                // Data channels can be created prior to the SCTP transport being available.
                // They will act as placeholders and then be opened once the SCTP transport 
                // becomes available.
                dataChannels.AddPendingChannel(channel);
                return channel;
            }
        }

        /// <summary>
        /// Sends the Data Channel Establishment Protocol (DCEP) OPEN message to configure the data
        /// channel on the remote peer.
        /// </summary>
        /// <param name="dataChannel">The data channel to open.</param>
        private void OpenDataChannel(RTCDataChannel dataChannel)
        {
            if (dataChannel.Negotiated)
            {
                Logger.LogDebug(
                    $"WebRTC data channel negotiated out of band with label {dataChannel.Label} and stream ID {dataChannel.Id}; invoking open event");
                dataChannel.GotAck();
            }
            else if (dataChannel.Id.HasValue)
            {
                Logger.LogDebug($"WebRTC attempting to open data channel with label {dataChannel.Label} and stream ID {dataChannel.Id}.");
                dataChannel.SendDcepOpen();
            }
            else
            {
                Logger.LogError("Attempt to open a data channel without an assigned ID has failed.");
            }
        }

        /// <summary>
        ///  DtlsHandshake requires DtlsSrtpTransport to work.
        ///  DtlsSrtpTransport is similar to C++ DTLS class combined with Srtp class and can perform 
        ///  Handshake as Server or Client in same call. The constructor of transport require a DtlsStrpClient 
        ///  or DtlsSrtpServer to work.
        /// </summary>
        /// <param name="dtlsHandle">The DTLS transport handle to perform the handshake with.</param>
        /// <returns>True if the DTLS handshake is successful or false if not.</returns>
        private bool DoDtlsHandshake(DtlsSrtpTransport dtlsHandle)
        {
            Logger.LogDebug("RTCPeerConnection DoDtlsHandshake started.");

            var rtpChannel = PrimaryStream.GetRTPChannel();

            dtlsHandle.OnDataReady += (buf) =>
            {
                //logger.LogDebug($"DTLS transport sending {buf.Length} bytes to {AudioDestinationEndPoint}.");
                rtpChannel.Send(RTPChannelSocketsEnum.RTP, PrimaryStream.DestinationEndPoint, buf);
            };

            var handshakeResult = dtlsHandle.DoHandshake(out var handshakeError);

            if (!handshakeResult)
            {
                handshakeError = handshakeError ?? "unknown";
                Logger.LogWarning($"RTCPeerConnection DTLS handshake failed with error {handshakeError}.");
                Close("dtls handshake failed");
                return false;
            }
            else
            {
                Logger.LogDebug(
                    $"RTCPeerConnection DTLS handshake result {handshakeResult}, is handshake complete {dtlsHandle.IsHandshakeComplete()}.");

                var expectedFp = RemotePeerDtlsFingerprint;
                var remoteFingerprint = DtlsUtils.Fingerprint(expectedFp.algorithm, dtlsHandle.GetRemoteCertificate().GetCertificateAt(0));

                if (remoteFingerprint.value?.ToUpper() != expectedFp.value?.ToUpper())
                {
                    Logger.LogWarning(
                        $"RTCPeerConnection remote certificate fingerprint mismatch, expected {expectedFp}, actual {remoteFingerprint}.");
                    Close("dtls fingerprint mismatch");
                    return false;
                }
                else
                {
                    Logger.LogDebug(
                        $"RTCPeerConnection remote certificate fingerprint matched expected value of {remoteFingerprint.value} for {remoteFingerprint.algorithm}.");

                    SetGlobalSecurityContext(dtlsHandle.ProtectRTP,
                        dtlsHandle.UnprotectRTP,
                        dtlsHandle.ProtectRTCP,
                        dtlsHandle.UnprotectRTCP);


                    IsDtlsNegotiationComplete = true;

                    return true;
                }
            }
        }

        /// <summary>
        /// Event handler for TLS alerts from the DTLS transport.
        /// </summary>
        /// <param name="alertLevel">The level of the alert: warning or critical.</param>
        /// <param name="alertType">The type of the alert.</param>
        /// <param name="alertDescription">An optional description for the alert.</param>
        private void OnDtlsAlert(AlertLevelsEnum alertLevel, AlertTypesEnum alertType, string alertDescription)
        {
            if (alertType == AlertTypesEnum.CloseNotify)
            {
                Logger.LogDebug($"SCTP closing transport as a result of DTLS close notification.");

                // No point keeping the SCTP association open if there is no DTLS transport available.
                Sctp?.Close();
            }
            else
            {
                string alertMsg = !string.IsNullOrEmpty(alertDescription) ? $": {alertDescription}" : ".";
                Logger.LogWarning($"DTLS unexpected {alertLevel} alert {alertType}{alertMsg}");
            }
        }

        /// <summary>
        /// Close the session if the instance is out of scope.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            Close("disposed");
        }

        /// <summary>
        /// Close the session if the instance is out of scope.
        /// </summary>
        public override void Dispose()
        {
            Close("disposed");
        }
    }
}

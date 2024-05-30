//-----------------------------------------------------------------------------
// Filename: DtlsSrtpServer.cs
//
// Description: This class represents the DTLS SRTP server connection handler.
//
// Derived From:
// https://github.com/RestComm/media-core/blob/master/rtp/src/main/java/org/restcomm/media/core/rtp/crypto/DtlsSrtpServer.java
//
// Author(s):
// Rafael Soares (raf.csoares@kyubinteractive.com)
//
// History:
// 01 Jul 2020	Rafael Soares   Created.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
// Original Source: AGPL-3.0 License
//-----------------------------------------------------------------------------

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Utilities;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public enum AlertLevelsEnum : byte
    {
        Warning = 1,
        Fatal = 2
    }

    public enum AlertTypesEnum : byte
    {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        DecryptionFailed = 21,
        RecordOverflow = 22,
        DecompressionFailure = 30,
        HandshakeFailure = 40,
        NoCertificate = 41,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknown = 46,
        IllegalParameter = 47,
        UnknownCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ExportRestriction = 60,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        InappropriateFallback = 86,
        UserCanceled = 90,
        NoRenegotiation = 100,
        UnsupportedExtension = 110,
        CertificateUnobtainable = 111,
        UnrecognizedName = 112,
        BadCertificateStatusResponse = 113,
        BadCertificateHashValue = 114,
        UnknownPskIdentity = 115,
        Unknown = 255
    }

    public interface IDtlsSrtpPeer
    {
        event Action<AlertLevelsEnum, AlertTypesEnum, string> OnAlert;
        bool ForceUseExtendedMasterSecret { get; set; }
        SrtpPolicy? GetSrtpPolicy();
        SrtpPolicy? GetSrtcpPolicy();
        byte[]? GetSrtpMasterServerKey();
        byte[]? GetSrtpMasterServerSalt();
        byte[]? GetSrtpMasterClientKey();
        byte[]? GetSrtpMasterClientSalt();
        bool IsClient();
        Certificate? GetRemoteCertificate();
    }

    public class DtlsSrtpServer : DefaultTlsServer, IDtlsSrtpPeer
    {
        private static readonly ILogger Logger = Log.Logger;

        public bool ForceUseExtendedMasterSecret { get; set; } = true;

        public Certificate? ClientCertificate { get; private set; }

        // the server response to the client handshake request
        // http://tools.ietf.org/html/rfc5764#section-4.1.1
        private UseSrtpData? serverSrtpData;

        // Asymmetric shared keys derived from the DTLS handshake and used for the SRTP encryption/
        private byte[]? srtpMasterClientKey;
        private byte[]? srtpMasterServerKey;
        private byte[]? srtpMasterClientSalt;
        private byte[]? srtpMasterServerSalt;
        private byte[]? masterSecret;

        // Policies
        private SrtpPolicy? srtpPolicy;
        private SrtpPolicy? srtcpPolicy;

        private readonly int[] cipherSuites;

        /// <summary>
        /// Parameters:
        ///  - alert level,
        ///  - alert type,
        ///  - alert description.
        /// </summary>
        public event Action<AlertLevelsEnum, AlertTypesEnum, string>? OnAlert;

        public DtlsSrtpServer() : this((Certificate?)null, null)
        {
        }

        public DtlsSrtpServer(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate) : this(
            DtlsUtils.LoadCertificateChain(certificate),
            DtlsUtils.LoadPrivateKeyResource(certificate))
        {
        }

        public DtlsSrtpServer(string certificatePath, string keyPath) : this([certificatePath], keyPath)
        {
        }

        public DtlsSrtpServer(string[] certificatesPath, string keyPath) :
            this(DtlsUtils.LoadCertificateChain(certificatesPath), DtlsUtils.LoadPrivateKeyResource(keyPath))
        {
        }

        public DtlsSrtpServer(Certificate? certificateChain, AsymmetricKeyParameter? privateKey)
        {
            if (certificateChain == null || privateKey == null)
            {
                (certificateChain, privateKey) = DtlsUtils.CreateSelfSignedTlsCert();
            }

            cipherSuites = base.GetCipherSuites();

            PrivateKey = privateKey;
            CertificateChain = certificateChain;

            //Generate FingerPrint
            var certificate = CertificateChain.GetCertificateAt(0);

            FingerPrint = certificate != null ? DtlsUtils.Fingerprint(certificate) : null;
        }

        public RTCDtlsFingerprint? FingerPrint { get; }

        public AsymmetricKeyParameter PrivateKey { get; }

        public Certificate CertificateChain { get; }

        protected override ProtocolVersion MaximumVersion => ProtocolVersion.DTLSv12;

        protected override ProtocolVersion MinimumVersion => ProtocolVersion.DTLSv10;

        public override int GetSelectedCipherSuite()
        {
            /*
             * TODO RFC 5246 7.4.3. In order to negotiate correctly, the server MUST check any candidate cipher suites against the
             * "signature_algorithms" extension before selecting them. This is somewhat inelegant but is a compromise designed to
             * minimize changes to the original cipher suite design.
             */

            /*
             * RFC 4429 5.1. A server that receives a ClientHello containing one or both of these extensions MUST use the client's
             * enumerated capabilities to guide its selection of an appropriate cipher suite. One of the proposed ECC cipher suites
             * must be negotiated only if the server can successfully complete the handshake while using the curves and point
             * formats supported by the client [...].
             */
            var eccCipherSuitesEnabled = SupportsClientEccCapabilities(this.mNamedCurves, this.mClientECPointFormats);

            var localCipherSuites = GetCipherSuites();
            foreach (var cipherSuite in localCipherSuites)
            {
                if (Arrays.Contains(this.mOfferedCipherSuites, cipherSuite) &&
                    (eccCipherSuitesEnabled || !TlsEccUtilities.IsEccCipherSuite(cipherSuite)) &&
                    TlsUtilities.IsValidCipherSuiteForVersion(cipherSuite, mServerVersion))
                {
                    return mSelectedCipherSuite = cipherSuite;
                }
            }
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        public override CertificateRequest GetCertificateRequest()
        {
            var signatureAndHashAlgorithms = new List<SignatureAndHashAlgorithm>();

            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(mServerVersion))
            {
                var hashAlgorithms = new[]
                    { HashAlgorithm.sha512, HashAlgorithm.sha384, HashAlgorithm.sha256, HashAlgorithm.sha224, HashAlgorithm.sha1 };
                var signatureAlgorithms = new[] { SignatureAlgorithm.rsa, SignatureAlgorithm.ecdsa };

                signatureAndHashAlgorithms = hashAlgorithms.SelectMany(_ => signatureAlgorithms,
                    (hashAlgorithm, signatureAlgorithm) => new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm)).ToList();
            }
            return new CertificateRequest([ClientCertificateType.rsa_sign, ClientCertificateType.ecdsa_sign], signatureAndHashAlgorithms, null);
        }

        public override void NotifyClientCertificate(Certificate clientCertificate)
        {
            ClientCertificate = clientCertificate;
        }

        public override IDictionary GetServerExtensions()
        {
            Hashtable serverExtensions = (Hashtable)base.GetServerExtensions();
            if (TlsSRTPUtils.GetUseSrtpExtension(serverExtensions) == null)
            {
                serverExtensions ??= new Hashtable();
                TlsSRTPUtils.AddUseSrtpExtension(serverExtensions, serverSrtpData);
            }
            return serverExtensions;
        }

        public override void ProcessClientExtensions(IDictionary clientExtensions)
        {
            base.ProcessClientExtensions(clientExtensions);

            // set to some reasonable default value
            var chosenProfile = SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80;
            var clientSrtpData = TlsSRTPUtils.GetUseSrtpExtension(clientExtensions);

            foreach (var profile in clientSrtpData.ProtectionProfiles)
            {
                switch (profile)
                {
                    case SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32:
                    case SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80:
                    case SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32:
                    case SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80:
                        chosenProfile = profile;
                        break;
                }
            }

            // server chooses a mutually supported SRTP protection profile
            // http://tools.ietf.org/html/draft-ietf-avt-dtls-srtp-07#section-4.1.2
            int[] protectionProfiles = [chosenProfile];

            // server agrees to use the MKI offered by the client
            serverSrtpData = new UseSrtpData(protectionProfiles, clientSrtpData.Mki);
        }

        public SrtpPolicy? GetSrtpPolicy()
        {
            return srtpPolicy;
        }

        public SrtpPolicy? GetSrtcpPolicy()
        {
            return srtcpPolicy;
        }

        public byte[]? GetSrtpMasterServerKey()
        {
            return srtpMasterServerKey;
        }

        public byte[]? GetSrtpMasterServerSalt()
        {
            return srtpMasterServerSalt;
        }

        public byte[]? GetSrtpMasterClientKey()
        {
            return srtpMasterClientKey;
        }

        public byte[]? GetSrtpMasterClientSalt()
        {
            return srtpMasterClientSalt;
        }

        public override void NotifyHandshakeComplete()
        {
            //Copy master Secret (will be inaccessible after this call)
            masterSecret = new byte[mContext.SecurityParameters.MasterSecret.Length];
            Buffer.BlockCopy(mContext.SecurityParameters.MasterSecret, 0, masterSecret, 0, masterSecret.Length);

            //Prepare Srtp Keys (we must to it here because master key will be cleared after that)
            PrepareSrtpSharedSecret();
        }

        public bool IsClient()
        {
            return false;
        }

        protected override TlsSignerCredentials GetECDsaSignerCredentials()
        {
            return DtlsUtils.LoadSignerCredentials(mContext,
                CertificateChain,
                PrivateKey,
                new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));
        }

        protected override TlsEncryptionCredentials GetRsaEncryptionCredentials()
        {
            return DtlsUtils.LoadEncryptionCredentials(mContext, CertificateChain, PrivateKey);
        }

        protected override TlsSignerCredentials? GetRsaSignerCredentials()
        {
            /*
             * TODO Note that this code fails to provide default value for the client supported
             * algorithms if it wasn't sent.
             */
            SignatureAndHashAlgorithm? signatureAndHashAlgorithm = null;
            var sigAlgs = mSupportedSignatureAlgorithms;
            if (sigAlgs != null)
            {
                foreach (var sigAlgUncasted in sigAlgs)
                {
                    if (sigAlgUncasted is SignatureAndHashAlgorithm { Signature: SignatureAlgorithm.rsa } sigAlg)
                    {
                        signatureAndHashAlgorithm = sigAlg;
                        break;
                    }
                }

                if (signatureAndHashAlgorithm == null)
                {
                    return null;
                }
            }
            return DtlsUtils.LoadSignerCredentials(mContext, CertificateChain, PrivateKey, signatureAndHashAlgorithm);
        }

        protected virtual void PrepareSrtpSharedSecret()
        {
            // Set master secret back to security parameters (only works in old bouncy castle versions)
            // mContext.SecurityParameters.masterSecret = masterSecret;
            Debug.Assert(serverSrtpData != null);

            var srtpParams = SrtpParameters.GetSrtpParametersForProfile(serverSrtpData!.ProtectionProfiles[0]);
            var keyLen = srtpParams.GetCipherKeyLength();
            var saltLen = srtpParams.GetCipherSaltLength();

            srtpPolicy = srtpParams.GetSrtpPolicy();
            srtcpPolicy = srtpParams.GetSrtcpPolicy();

            srtpMasterClientKey = new byte[keyLen];
            srtpMasterServerKey = new byte[keyLen];
            srtpMasterClientSalt = new byte[saltLen];
            srtpMasterServerSalt = new byte[saltLen];

            // 2* (key + salt length) / 8. From http://tools.ietf.org/html/rfc5764#section-4-2
            // No need to divide by 8 here since lengths are already in bits
            byte[] sharedSecret = GetKeyingMaterial(2 * (keyLen + saltLen));

            /*
             *
             * See: http://tools.ietf.org/html/rfc5764#section-4.2
             *
             * sharedSecret is an equivalent of :
             *
             * struct {
             *     client_write_SRTP_master_key[SRTPSecurityParams.master_key_len];
             *     server_write_SRTP_master_key[SRTPSecurityParams.master_key_len];
             *     client_write_SRTP_master_salt[SRTPSecurityParams.master_salt_len];
             *     server_write_SRTP_master_salt[SRTPSecurityParams.master_salt_len];
             *  } ;
             *
             * Here, client = local configuration, server = remote.
             * NOTE [ivelin]: 'local' makes sense if this code is used from a DTLS SRTP client.
             *                Here we run as a server, so 'local' referring to the client is actually confusing.
             *
             * l(k) = KEY length
             * s(k) = salt length
             *
             * So we have the following repartition :
             *                           l(k)                                 2*l(k)+s(k)
             *                                                   2*l(k)                       2*(l(k)+s(k))
             * +------------------------+------------------------+---------------+-------------------+
             * + local key           |    remote key    | local salt   | remote salt   |
             * +------------------------+------------------------+---------------+-------------------+
             */
            Buffer.BlockCopy(sharedSecret, 0, srtpMasterClientKey, 0, keyLen);
            Buffer.BlockCopy(sharedSecret, keyLen, srtpMasterServerKey, 0, keyLen);
            Buffer.BlockCopy(sharedSecret, 2 * keyLen, srtpMasterClientSalt, 0, saltLen);
            Buffer.BlockCopy(sharedSecret, (2 * keyLen + saltLen), srtpMasterServerSalt, 0, saltLen);
        }

        protected byte[] GetKeyingMaterial(int length)
        {
            return GetKeyingMaterial(ExporterLabel.dtls_srtp, null, length);
        }

        protected virtual byte[] GetKeyingMaterial(string asciiLabel, byte[]? contextValue, int length)
        {
            if (contextValue != null && !TlsUtilities.IsValidUint16(contextValue.Length))
            {
                throw new ArgumentException("must have length less than 2^16 (or be null)", nameof(contextValue));
            }

            var sp = mContext.SecurityParameters;
            if (!sp.IsExtendedMasterSecret && RequiresExtendedMasterSecret())
            {
                /*
                 * RFC 7627 5.4. If a client or server chooses to continue with a full handshake without
                 * the extended master secret extension, [..] the client or server MUST NOT export any
                 * key material based on the new master secret for any subsequent application-level
                 * authentication. In particular, it MUST disable [RFC5705] [..].
                 */
                throw new InvalidOperationException("cannot export keying material without extended_master_secret");
            }

            byte[] cr = sp.ClientRandom, sr = sp.ServerRandom;

            var seedLength = cr.Length + sr.Length;
            if (contextValue != null)
            {
                seedLength += (2 + contextValue.Length);
            }

            var seed = new byte[seedLength];
            var seedPos = 0;

            Array.Copy(cr, 0, seed, seedPos, cr.Length);
            seedPos += cr.Length;
            Array.Copy(sr, 0, seed, seedPos, sr.Length);
            seedPos += sr.Length;
            if (contextValue != null)
            {
                TlsUtilities.WriteUint16(contextValue.Length, seed, seedPos);
                seedPos += 2;
                Array.Copy(contextValue, 0, seed, seedPos, contextValue.Length);
                seedPos += contextValue.Length;
            }

            if (seedPos != seedLength)
            {
                throw new InvalidOperationException("error in calculation of seed for export");
            }

            return TlsUtilities.PRF(mContext, sp.MasterSecret, asciiLabel, seed, length);
        }

        public override bool RequiresExtendedMasterSecret()
        {
            return ForceUseExtendedMasterSecret;
        }

        protected override int[] GetCipherSuites()
        {
            var localCipherSuites = new int[cipherSuites.Length];
            for (var i = 0; i < cipherSuites.Length; i++)
            {
                localCipherSuites[i] = cipherSuites[i];
            }
            return localCipherSuites;
        }

        public Certificate? GetRemoteCertificate()
        {
            return ClientCertificate;
        }

        public override void NotifyAlertRaised(byte alertLevel, byte alertDescription, string? message, Exception? cause)
        {
            string? description = null;
            if (message != null)
            {
                description += message;
            }
            if (cause != null)
            {
                description += cause;
            }

            var alertMsg = $"{AlertLevel.GetText(alertLevel)}, {AlertDescription.GetText(alertDescription)}";
            alertMsg += !string.IsNullOrEmpty(description) ? $", {description}." : ".";

            if (alertDescription == AlertTypesEnum.CloseNotify.GetHashCode())
            {
                Logger.LogDebug($"DTLS server raised close notify: {alertMsg}");
            }
            else
            {
                Logger.LogWarning($"DTLS server raised unexpected alert: {alertMsg}");
            }
        }

        public override void NotifyAlertReceived(byte alertLevel, byte alertDescription)
        {
            var description = AlertDescription.GetText(alertDescription);

            var level = AlertLevelsEnum.Warning;
            var alertType = AlertTypesEnum.Unknown;

            if (Enum.IsDefined(typeof(AlertLevelsEnum), alertLevel))
            {
                level = (AlertLevelsEnum)alertLevel;
            }

            if (Enum.IsDefined(typeof(AlertTypesEnum), alertDescription))
            {
                alertType = (AlertTypesEnum)alertDescription;
            }

            var alertMsg = $"{AlertLevel.GetText(alertLevel)}";
            alertMsg += (!string.IsNullOrEmpty(description)) ? $", {description}." : ".";

            if (alertType == AlertTypesEnum.CloseNotify)
            {
                Logger.LogDebug($"DTLS server received close notification: {alertMsg}");
            }
            else
            {
                Logger.LogWarning($"DTLS server received unexpected alert: {alertMsg}");
            }

            OnAlert?.Invoke(level, alertType, description);
        }

        /// <summary>
        /// This override prevents a TLS fault from being generated if a "Client Hello" is received that
        /// does not support TLS renegotiation (https://tools.ietf.org/html/rfc5746).
        /// This override is required to be able to complete a DTLS handshake with the Pion WebRTC library,
        /// see https://github.com/pion/dtls/issues/274.
        /// </summary>
        public override void NotifySecureRenegotiation(bool secureRenegotiation)
        {
            if (!secureRenegotiation)
            {
                Logger.LogWarning($"DTLS server received a client handshake without renegotiation support.");
            }
        }
    }
}

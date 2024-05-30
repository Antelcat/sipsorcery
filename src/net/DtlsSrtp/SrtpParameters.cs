//-----------------------------------------------------------------------------
// Filename: SrtpParameters.cs
//
// Description: Parameters for Secure RTP (SRTP) sessions.
//
// Derived From: 
// https://github.com/RestComm/media-core/blob/master/rtp/src/main/java/org/restcomm/media/core/rtp/crypto/SRTPParameters.java
//
// Author(s):
// Rafael Soares (raf.csoares@kyubinteractive.com)
//
// History:
// 01 Jul 2020	Rafael Soares   Created.
//
// License:
// Customisations: BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
// Original Source: AGPL-3.0 License
//-----------------------------------------------------------------------------

using System;
using Org.BouncyCastle.Crypto.Tls;

namespace SIPSorcery.Net;

public struct SrtpParameters
{
    // DTLS derived key and salt lengths for SRTP 
    // http://tools.ietf.org/html/rfc5764#section-4.1.2

    //	SRTP_AES128_CM_HMAC_SHA1_80 (SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, SRTPPolicy.AESCM_ENCRYPTION, 128, SRTPPolicy.HMACSHA1_AUTHENTICATION, 160, 80, 80, 112),
    //	SRTP_AES128_CM_HMAC_SHA1_32 (SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32, SRTPPolicy.AESCM_ENCRYPTION, 128, SRTPPolicy.HMACSHA1_AUTHENTICATION, 160, 32, 80, 112),
    // hrosa - converted lengths to work with bytes, not bits (1 byte = 8 bits)
    public static readonly SrtpParameters SRTP_AES128_CM_HMAC_SHA1_80 = new(SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, SrtpPolicy.AESCM_ENCRYPTION, 16, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 10, 10, 14);
    public static readonly SrtpParameters SRTP_AES128_CM_HMAC_SHA1_32 = new(SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32, SrtpPolicy.AESCM_ENCRYPTION, 16, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 4, 10, 14);
    public static readonly SrtpParameters SRTP_NULL_HMAC_SHA1_80 = new(SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80, SrtpPolicy.NULL_ENCRYPTION, 0, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 10, 10, 0);
    public static readonly SrtpParameters SRTP_NULL_HMAC_SHA1_32 = new(SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32, SrtpPolicy.NULL_ENCRYPTION, 0, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 4, 10, 0);
    
    private readonly int profile;
    private readonly int encType;
    private readonly int encKeyLength;
    private readonly int authType;
    private readonly int authKeyLength;
    private readonly int authTagLength;
    private readonly int rtcpAuthTagLength;
    private readonly int saltLength;

    private SrtpParameters(int newProfile, int newEncType, int newEncKeyLength, int newAuthType, int newAuthKeyLength, int newAuthTagLength, int newRtcpAuthTagLength, int newSaltLength)
    {
        profile = newProfile;
        encType = newEncType;
        encKeyLength = newEncKeyLength;
        authType = newAuthType;
        authKeyLength = newAuthKeyLength;
        authTagLength = newAuthTagLength;
        rtcpAuthTagLength = newRtcpAuthTagLength;
        saltLength = newSaltLength;
    }

    public int GetProfile()
    {
        return profile;
    }

    public readonly int GetCipherKeyLength()
    {
        return encKeyLength;
    }

    public readonly int GetCipherSaltLength()
    {
        return saltLength;
    }

    public static SrtpParameters GetSrtpParametersForProfile(int profileValue)
    {
        switch (profileValue)
        {
            case SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80:
                return SRTP_AES128_CM_HMAC_SHA1_80;
            case SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32:
                return SRTP_AES128_CM_HMAC_SHA1_32;
            case SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80:
                return SRTP_NULL_HMAC_SHA1_80;
            case SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32:
                return SRTP_NULL_HMAC_SHA1_32;
            default:
                throw new Exception($"SRTP Protection Profile value {profileValue} is not allowed for DTLS SRTP. See http://tools.ietf.org/html/rfc5764#section-4.1.2 for valid values.");
        }
    }

    public SrtpPolicy GetSrtpPolicy()
    {
        return new SrtpPolicy(encType, encKeyLength, authType, authKeyLength, authTagLength, saltLength);
    }

    public SrtpPolicy GetSrtcpPolicy()
    {
        return new SrtpPolicy(encType, encKeyLength, authType, authKeyLength, rtcpAuthTagLength, saltLength);
    }
}
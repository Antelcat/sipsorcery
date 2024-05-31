//-----------------------------------------------------------------------------
// Filename: SctpDataReceiver.cs
//
// Description: This class is used to collate incoming DATA chunks into full
// frames.
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
// 
// History:
// 29 Mar 2021	Aaron Clauson	Created, Dublin, Ireland.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace SIPSorcery.Net;

public struct SctpDataFrame
{
    public static SctpDataFrame Empty = new();

    public bool Unordered { get; }
    public ushort StreamID { get; }
    public ushort StreamSeqNum { get; }
    public uint PPID { get; }
    public byte[] UserData { get; set; }

    /// <param name="streamID">The stream ID of the chunk.</param>
    /// <param name="streamSeqNum">The stream sequence number of the chunk. Will be 0 for unordered streams.</param>
    /// <param name="ppid">The payload protocol ID for the chunk.</param>
    /// <param name="userData">The chunk data.</param>
    public SctpDataFrame(bool unordered, ushort streamID, ushort streamSeqNum, uint ppid, byte[] userData)
    {
        Unordered = unordered;
        StreamID = streamID;
        StreamSeqNum = streamSeqNum;
        PPID = ppid;
        UserData = userData;
    }

    public bool IsEmpty()
    {
        return UserData == null;
    }
}

public struct SctpTsnGapBlock
{
    /// <summary>
    /// Indicates the Start offset TSN for this Gap Ack Block.  To
    /// calculate the actual TSN number the Cumulative TSN Ack is added to
    /// this offset number.This calculated TSN identifies the first TSN
    /// in this Gap Ack Block that has been received.
    /// </summary>
    public ushort Start;

    /// <summary>
    /// Indicates the End offset TSN for this Gap Ack Block.  To calculate
    /// the actual TSN number, the Cumulative TSN Ack is added to this
    /// offset number.This calculated TSN identifies the TSN of the last
    /// DATA chunk received in this Gap Ack Block.
    /// </summary>
    public ushort End;
}

/// <summary>
/// Processes incoming data chunks and handles fragmentation and congestion control. This
/// class does NOT handle in order delivery. Different streams on the same association
/// can have different ordering requirements so it's left up to each stream handler to
/// deal with full frames as they see fit.
/// </summary>
public class SctpDataReceiver
{
    /// <summary>
    /// The window size is the maximum number of entries that can be recorded in the 
    /// <see cref="_receivedChunks"/> dictionary.
    /// </summary>
    private const ushort WINDOW_SIZE_MINIMUM = 100;

    /// <summary>
    /// The maximum number of out of order frames that will be queued per stream ID.
    /// </summary>
    private const int MAXIMUM_OUTOFORDER_FRAMES = 25;

    /// <summary>
    /// The maximum size of an SCTP fragmented message.
    /// </summary>
    private const int MAX_FRAME_SIZE = 262144;

    private readonly static ILogger Logger = LogFactory.CreateLogger<SctpDataReceiver>();

    /// <summary>
    /// This dictionary holds data chunk Transaction Sequence Numbers (TSN) that have
    /// been received out of order and are in advance of the expected TSN.
    /// </summary>
    private readonly SortedDictionary<uint, int> forwardTSN = new();

    /// <summary>
    /// Storage for fragmented chunks.
    /// </summary>
    private readonly Dictionary<uint, SctpDataChunk> fragmentedChunks = new();

    /// <summary>
    /// Keeps track of the latest sequence number for each stream. Used to ensure
    /// stream chunks are delivered in order.
    /// </summary>
    private readonly Dictionary<ushort, ushort> streamLatestSeqNums = new();

    /// <summary>
    /// A dictionary of dictionaries used to hold out of order stream chunks.
    /// </summary>
    private readonly Dictionary<ushort, Dictionary<ushort, SctpDataFrame>> streamOutOfOrderFrames = new();

    /// <summary>
    /// The maximum amount of received data that will be stored at any one time.
    /// This is part of the SCTP congestion window mechanism. It limits the number
    /// of bytes, a sender can send to a particular destination transport address 
    /// before receiving an acknowledgement.
    /// </summary>
    private readonly uint receiveWindow;

    /// <summary>
    /// The most recent in order TSN received. This is the value that gets used
    /// in the "Cumulative TSN Ack" field to SACK chunks. 
    /// </summary>
    private uint lastInOrderTSN;

    /// <summary>
    /// The window size is the maximum number of chunks we're prepared to hold in the 
    /// receive dictionary.
    /// </summary>
    private readonly ushort windowSize;

    /// <summary>
    /// Record of the duplicate Transaction Sequence Number (TSN) chunks received since
    /// the last SACK chunk was generated.
    /// </summary>
    private readonly Dictionary<uint, int> duplicateTSN = new();

    /// <summary>
    /// Gets the Transaction Sequence Number (TSN) that can be acknowledged to the remote peer.
    /// It represents the most recent in order TSN that has been received. If no in order
    /// TSN's have been received then null will be returned.
    /// </summary>
    public uint? CumulativeAckTSN => inOrderReceiveCount > 0 ? lastInOrderTSN : null;

    /// <summary>
    /// A count of the total entries in the receive dictionary. Note that if chunks
    /// have been received out of order this count could include chunks that have
    /// already been processed. They are kept in the dictionary as empty chunks to
    /// track which TSN's have been received.
    /// </summary>
    public int ForwardTSNCount => forwardTSN.Count;

    private uint initialTSN;
    private uint inOrderReceiveCount;

    /// <summary>
    /// Creates a new SCTP data receiver instance.
    /// </summary>
    /// <param name="receiveWindow">The size of the receive window. This is the window around the 
    /// expected Transaction Sequence Number (TSN). If a data chunk is received with a TSN outside
    /// the window it is ignored.</param>
    /// <param name="mtu">The Maximum Transmission Unit for the network layer that the SCTP
    /// association is being used with.</param>
    /// <param name="initialTSN">The initial TSN for the association from the INIT handshake.</param>
    public SctpDataReceiver(uint receiveWindow, uint mtu, uint initialTSN)
    {
        this.receiveWindow = receiveWindow != 0 ? receiveWindow : SctpAssociation.DEFAULT_ADVERTISED_RECEIVE_WINDOW;
        this.initialTSN = initialTSN;

        mtu = mtu != 0 ? mtu : SctpUdpTransport.DEFAULT_UDP_MTU;
        windowSize = (ushort)(this.receiveWindow / mtu);
        windowSize = (windowSize < WINDOW_SIZE_MINIMUM) ? WINDOW_SIZE_MINIMUM : windowSize;

        Logger.LogDebug($"SCTP windows size for data receiver set at {windowSize}.");
    }

    /// <summary>
    /// Used to set the initial TSN for the remote party when it's not known at creation time.
    /// </summary>
    /// <param name="tsn">The initial Transaction Sequence Number (TSN) for the 
    /// remote party.</param>
    public void SetInitialTSN(uint tsn)
    {
        initialTSN = tsn;
    }

    /// <summary>
    /// Handler for processing new data chunks.
    /// </summary>
    /// <param name="dataChunk">The newly received data chunk.</param>
    /// <returns>If the received chunk resulted in a full chunk becoming available one 
    /// or more new frames will be returned otherwise an empty frame is returned. Multiple
    /// frames may be returned if this chunk is part of a stream and was received out
    /// or order. For unordered chunks the list will always have a single entry.</returns>
    public List<SctpDataFrame> OnDataChunk(SctpDataChunk dataChunk)
    {
        var sortedFrames = new List<SctpDataFrame>();
        var frame = SctpDataFrame.Empty;

        if (inOrderReceiveCount == 0 &&
            GetDistance(initialTSN, dataChunk.TSN) > windowSize)
        {
            Logger.LogWarning($"SCTP data receiver received a data chunk with a {dataChunk.TSN} " +
                              $"TSN when the initial TSN was {initialTSN} and a " +
                              $"window size of {windowSize}, ignoring.");
        }
        else if (inOrderReceiveCount > 0 &&
                 GetDistance(lastInOrderTSN, dataChunk.TSN) > windowSize)
        {
            Logger.LogWarning($"SCTP data receiver received a data chunk with a {dataChunk.TSN} " +
                              $"TSN when the expected TSN was {lastInOrderTSN + 1} and a " +
                              $"window size of {windowSize}, ignoring.");
        }
        else if (inOrderReceiveCount > 0 &&
                 !IsNewer(lastInOrderTSN, dataChunk.TSN))
        {
            Logger.LogWarning($"SCTP data receiver received an old data chunk with {dataChunk.TSN} " +
                              $"TSN when the expected TSN was {lastInOrderTSN + 1}, ignoring.");
        }
        else if (!forwardTSN.ContainsKey(dataChunk.TSN))
        {
            Logger.LogTrace($"SCTP receiver got data chunk with TSN {dataChunk.TSN}, " +
                            $"last in order TSN {lastInOrderTSN}, in order receive count {inOrderReceiveCount}.");

            bool processFrame = true;

            // Relying on unsigned integer wrapping.
            unchecked
            {
                if ((inOrderReceiveCount > 0 && lastInOrderTSN + 1 == dataChunk.TSN) ||
                    (inOrderReceiveCount == 0 && dataChunk.TSN == initialTSN))
                {
                    inOrderReceiveCount++;
                    lastInOrderTSN = dataChunk.TSN;

                    // See if the in order TSN can be bumped using any out of order chunks 
                    // already received.
                    if (inOrderReceiveCount > 0 && forwardTSN.Count > 0)
                    {
                        while (forwardTSN.ContainsKey(lastInOrderTSN + 1))
                        {
                            lastInOrderTSN++;
                            inOrderReceiveCount++;
                            forwardTSN.Remove(lastInOrderTSN);
                        }
                    }
                }
                else
                {
                    if (!dataChunk.Unordered &&
                        streamOutOfOrderFrames.TryGetValue(dataChunk.StreamID, out var outOfOrder) &&
                        outOfOrder.Count >= MAXIMUM_OUTOFORDER_FRAMES)
                    {
                        // Stream is nearing capacity, only chunks that advance _lastInOrderTSN can be accepted. 
                        Logger.LogWarning($"Stream {dataChunk.StreamID} is at buffer capacity. Rejected out-of-order data chunk TSN {dataChunk.TSN}.");
                        processFrame = false;
                    }
                    else
                    {
                        forwardTSN.Add(dataChunk.TSN, 1);
                    }
                }
            }

            if (processFrame)
            {
                // Now go about processing the data chunk.
                if (dataChunk.Begining && dataChunk.Ending)
                {
                    // Single packet chunk.
                    frame = new SctpDataFrame(
                        dataChunk.Unordered,
                        dataChunk.StreamID,
                        dataChunk.StreamSeqNum,
                        dataChunk.PPID,
                        dataChunk.UserData);
                }
                else
                {
                    // This is a data chunk fragment.
                    fragmentedChunks.Add(dataChunk.TSN, dataChunk);
                    var (begin, end) = GetChunkBeginAndEnd(fragmentedChunks, dataChunk.TSN);

                    if (begin != null && end != null)
                    {
                        frame = GetFragmentedChunk(fragmentedChunks, begin.Value, end.Value);
                    }
                }
            }
        }
        else
        {
            Logger.LogTrace($"SCTP duplicate TSN received for {dataChunk.TSN}.");
            if (!duplicateTSN.ContainsKey(dataChunk.TSN))
            {
                duplicateTSN.Add(dataChunk.TSN, 1);
            }
            else
            {
                duplicateTSN[dataChunk.TSN] = duplicateTSN[dataChunk.TSN] + 1;
            }
        }

        if (!frame.IsEmpty() && !dataChunk.Unordered)
        {
            return ProcessStreamFrame(frame);
        }
        else
        {
            if (!frame.IsEmpty())
            {
                sortedFrames.Add(frame);
            }

            return sortedFrames;
        }
    }

    /// <summary>
    /// Gets a SACK chunk that represents the current state of the receiver.
    /// </summary>
    /// <returns>A SACK chunk that can be sent to the remote peer to update the ACK TSN and
    /// request a retransmit of any missing DATA chunks.</returns>
    public SctpSackChunk? GetSackChunk()
    {
        // Can't create a SACK until the initial DATA chunk has been received.
        if (inOrderReceiveCount > 0)
        {
            var sack = new SctpSackChunk(lastInOrderTSN, receiveWindow)
            {
                GapAckBlocks = GetForwardTSNGaps(),
                DuplicateTSN = duplicateTSN.Keys.ToList(),
            };
            return sack;
        }
            
        return null;
    }

    /// <summary>
    /// Gets a list of the gaps in the forward TSN records. Typically the TSN gap
    /// reports are used in SACK chunks to inform the remote peer which DATA chunk
    /// TSNs have not yet been received.
    /// </summary>
    /// <returns>A list of TSN gap blocks. An empty list means there are no gaps.</returns>
    internal List<SctpTsnGapBlock> GetForwardTSNGaps()
    {
        var gaps = new List<SctpTsnGapBlock>();

        // Can't create gap reports until the initial DATA chunk has been received.
        if (inOrderReceiveCount > 0)
        {
            var tsnAck = lastInOrderTSN;

            if (forwardTSN.Count > 0)
            {
                ushort? start = null;
                uint prev = 0;

                foreach (var tsn in forwardTSN.Keys)
                {
                    if (start == null)
                    {
                        start = (ushort)(tsn - tsnAck);
                        prev = tsn;
                    }
                    else if (tsn != prev + 1)
                    {
                        var end = (ushort)(prev - tsnAck);
                        gaps.Add(new SctpTsnGapBlock { Start = start.Value, End = end });
                        start = (ushort)(tsn - tsnAck);
                        prev = tsn;
                    }
                    else
                    {
                        prev++;
                    }
                }

                gaps.Add(new SctpTsnGapBlock { Start = start!.Value, End = (ushort)(prev - tsnAck) });
            }
        }

        return gaps;
    }

    /// <summary>
    /// Processes a data frame that is now ready and that is part of an SCTP stream.
    /// Stream frames must be delivered in order.
    /// </summary>
    /// <param name="frame">The data frame that became ready from the latest DATA chunk receive.</param>
    /// <returns>A sorted list of frames for the matching stream ID. Will be empty
    /// if the supplied frame is out of order for its stream.</returns>
    private List<SctpDataFrame> ProcessStreamFrame(SctpDataFrame frame)
    {
        // Relying on unsigned short wrapping.
        unchecked
        {
            // This is a stream chunk. Need to ensure in order delivery.
            var sortedFrames = new List<SctpDataFrame>();

            if (!streamLatestSeqNums.ContainsKey(frame.StreamID))
            {
                // First frame for this stream.
                streamLatestSeqNums.Add(frame.StreamID, frame.StreamSeqNum);
                sortedFrames.Add(frame);
            }
            else if ((ushort)(streamLatestSeqNums[frame.StreamID] + 1) == frame.StreamSeqNum)
            {
                // Expected seqnum for stream.
                streamLatestSeqNums[frame.StreamID] = frame.StreamSeqNum;
                sortedFrames.Add(frame);

                // There could also be out of order frames that can now be delivered.
                if (streamOutOfOrderFrames.ContainsKey(frame.StreamID) &&
                    streamOutOfOrderFrames[frame.StreamID].Count > 0)
                {
                    var outOfOrder = streamOutOfOrderFrames[frame.StreamID];

                    ushort nextSeqnum = (ushort)(streamLatestSeqNums[frame.StreamID] + 1);
                    while (outOfOrder.ContainsKey(nextSeqnum) &&
                           outOfOrder.TryGetValue(nextSeqnum, out var nextFrame))
                    {
                        sortedFrames.Add(nextFrame);
                        streamLatestSeqNums[frame.StreamID] = nextSeqnum;
                        outOfOrder.Remove(nextSeqnum);
                        nextSeqnum++;
                    }
                }
            }
            else
            {
                // Stream seqnum is out of order.
                if (!streamOutOfOrderFrames.ContainsKey(frame.StreamID))
                {
                    streamOutOfOrderFrames[frame.StreamID] = new Dictionary<ushort, SctpDataFrame>();
                }

                streamOutOfOrderFrames[frame.StreamID].Add(frame.StreamSeqNum, frame);
            }

            return sortedFrames;
        }
    }

    /// <summary>
    /// Checks whether the fragmented chunk for the supplied TSN is complete and if so
    /// returns its begin and end TSNs.
    /// </summary>
    /// <param name="tsn">The TSN of the fragmented chunk to check for completeness.</param>
    /// <param name="fragments">The dictionary containing the chunk fragments.</param>
    /// <returns>If the chunk is complete the begin and end TSNs will be returned. If
    /// the fragmented chunk is incomplete one or both of the begin and/or end TSNs will be null.</returns>
    private static (uint?, uint?) GetChunkBeginAndEnd(Dictionary<uint, SctpDataChunk> fragments, uint tsn)
    {
        unchecked
        {
            var beginTSN = fragments[tsn].Begining ? (uint?)tsn : null;
            var endTSN = fragments[tsn].Ending ? (uint?)tsn : null;

            var revTSN = tsn - 1;
            while (beginTSN == null && fragments.ContainsKey(revTSN))
            {
                if (fragments[revTSN].Begining)
                {
                    beginTSN = revTSN;
                }
                else
                {
                    revTSN--;
                }
            }

            if (beginTSN != null)
            {
                var fwdTSN = tsn + 1;
                while (endTSN == null && fragments.ContainsKey(fwdTSN))
                {
                    if (fragments[fwdTSN].Ending)
                    {
                        endTSN = fwdTSN;
                    }
                    else
                    {
                        fwdTSN++;
                    }
                }
            }

            return (beginTSN, endTSN);
        }
    }

    /// <summary>
    /// Extracts a fragmented chunk from the receive dictionary and passes it to the ULP.
    /// </summary>
    /// <param name="fragments">The dictionary containing the chunk fragments.</param>
    /// <param name="beginTSN">The beginning TSN for the fragment.</param>
    /// <param name="endTSN">The end TSN for the fragment.</param>
    private SctpDataFrame GetFragmentedChunk(Dictionary<uint, SctpDataChunk> fragments, uint beginTSN, uint endTSN)
    {
        unchecked
        {
            byte[] full = new byte[MAX_FRAME_SIZE];
            int posn = 0;
            var beginChunk = fragments[beginTSN];
            var frame = new SctpDataFrame(beginChunk.Unordered, beginChunk.StreamID, beginChunk.StreamSeqNum, beginChunk.PPID, full);

            uint afterEndTSN = endTSN + 1;
            uint tsn = beginTSN;

            while (tsn != afterEndTSN)
            {
                var fragment = fragments[tsn].UserData;
                Buffer.BlockCopy(fragment, 0, full, posn, fragment.Length);
                posn += fragment.Length;
                fragments.Remove(tsn);
                tsn++;
            }

            frame.UserData = frame.UserData.Take(posn).ToArray();

            return frame;
        }
    }

    /// <summary>
    /// Determines if a received TSN is newer than the expected TSN taking
    /// into account if TSN wrap around has occurred.
    /// </summary>
    /// <param name="tsn">The TSN to compare against.</param>
    /// <param name="receivedTSN">The received TSN.</param>
    /// <returns>True if the received TSN is newer than the reference TSN
    /// or false if not.</returns>
    public static bool IsNewer(uint tsn, uint receivedTSN)
    {
        if (tsn < uint.MaxValue / 2 && receivedTSN > uint.MaxValue / 2)
        {
            // TSN wrap has occurred and the received TSN is old.
            return false;
        }
        else if (tsn > uint.MaxValue / 2 && receivedTSN < uint.MaxValue / 2)
        {
            // TSN wrap has occurred and the received TSN is new.
            return true;
        }
        else
        {
            return receivedTSN > tsn;
        }
    }

    public static bool IsNewerOrEqual(uint tsn, uint receivedTSN)
    {
        return tsn == receivedTSN || IsNewer(tsn, receivedTSN);
    }

    /// <summary>
    /// Gets the distance between two unsigned integers. The "distance" means how many 
    /// points are there between the two unsigned integers and allows wrapping from
    /// the unsigned integer maximum to zero.
    /// </summary>
    /// <returns>The shortest distance between the two unsigned integers.</returns>
    public static uint GetDistance(uint start, uint end)
    {
        uint fwdDistance = end - start;
        uint backDistance = start - end;

        return (fwdDistance < backDistance) ? fwdDistance : backDistance;
    }
}
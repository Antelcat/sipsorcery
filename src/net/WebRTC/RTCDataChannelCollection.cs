using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace SIPSorcery.Net
{
    internal class RTCDataChannelCollection(Func<bool> useEvenIds) : IReadOnlyCollection<RTCDataChannel>
    {
        private readonly ConcurrentBag<RTCDataChannel> pendingChannels = [];
        private readonly ConcurrentDictionary<ushort, RTCDataChannel> activeChannels = new();

        private readonly object idSyncObj = new();
        private ushort lastChannelId = ushort.MaxValue - 1;

        public int Count => pendingChannels.Count + activeChannels.Count;

        public void AddPendingChannel(RTCDataChannel channel)
            => pendingChannels.Add(channel);

        public IEnumerable<RTCDataChannel> ActivatePendingChannels()
        {
            while (pendingChannels.TryTake(out var channel))
            {
                AddActiveChannel(channel);
                yield return channel;
            }
        }
        
        public bool TryGetChannel(ushort dataChannelID, out RTCDataChannel result)
            => activeChannels.TryGetValue(dataChannelID, out result);
        
        public bool AddActiveChannel(RTCDataChannel channel)
        {
            if (channel.Id.HasValue)
            {
                if (!activeChannels.TryAdd(channel.Id.Value, channel))
                {
                    return false;
                }
            }
            else
            {
                while (true)
                {
                    var id = GetNextChannelId();
                    if (activeChannels.TryAdd(id, channel))
                    {
                        channel.Id = id;
                        break;
                    }
                }
            }

            channel.OnClose += OnClose;
            channel.OnError += OnError;
            return true;
            
            void OnClose()
            {
                channel.OnClose -= OnClose;
                channel.OnError -= OnError;
                activeChannels.TryRemove(channel.Id.Value, out _);
            }
            void OnError(string error) => OnClose();
        }
        
        ushort GetNextChannelId()
        {
            lock (idSyncObj)
            {
                unchecked
                {
                    //  The SCTP stream identifier 65535 is reserved due to SCTP INIT and
                    // INIT - ACK chunks only allowing a maximum of 65535 streams to be
                    // negotiated(0 - 65534) - https://tools.ietf.org/html/rfc8832
                    if (lastChannelId == ushort.MaxValue - 3)
                    {
                        lastChannelId += 4;
                    }
                    else
                    {
                        lastChannelId += 2;
                    }
                }
                return useEvenIds() ? lastChannelId : (ushort) (lastChannelId + 1);
            }
        }

        public IEnumerator<RTCDataChannel> GetEnumerator()
            => pendingChannels.Concat(activeChannels.Select(e => e.Value)).GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

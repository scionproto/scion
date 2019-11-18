# SIG ingress pipeline

Incoming packets are processed in the following manner:

1. Disapatcher (singleton) object reads SIG frames from the network and passes them to
   an appropriate Worker based on the source IA, source host address and session ID.
1. Worker passes the frame to a ReassemblyList based on the epoch. Non-active epochs
   are purged in periodic manner.
1. ReassemblyList keeps a list of frames. It processes them in a lazy manner: It only
   parses the content once an entire IP packet can be assembled. The reason for this
   is that there may be holes in the frame sequence and in that case we want to drop
   the old frames. Which wouldn't be possible if the frames were processed immediately
   as they arrive.
1. Once a full packet is available, it is sent to the local network via the TUN device.

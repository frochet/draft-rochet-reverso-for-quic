---
title: "Reverso for the QUIC protocol"
category: std
docname: draft-frochet-quicwg-reverso-for-quic-latest
keyword: internet-draft
v: 3
workgroup: QUICWG
venue:
  group: QUICWG
  type: Working Group
  github: https://github.com/frochet/draft-rochet-reverso-for-quic

author:
 -
    fullname: Florentin Rochet
    organization: UNamur
    email: florentin.rochet@unamur.be

informative:
  RFC9000:
  RFC9001:

--- abstract

This document describes a QUIC version re-designing the layout of the
QUIC protocol to avoid memory fragmentation at the receiver and allows
implementers seeking a more efficient implementation to have the option
to implement contiguous zero-copy at the receiver. This document
describes the change from QUIC v1 required in packet formats,
variable-length integers and frame formats. Everything else from QUIC
v1 described in {{RFC9000}} is untouched.

--- middle

# Introduction

QUIC is a general-purpose transport protocol with mandatory encryption
leveraged from a TLS 1.3 key exchange. QUIC is specified in {{RFC9000}},
and is the result of several years of efforts from several major
companies, independent individuals and academics. One of the main
benefits of QUIC is to resist ossification thanks to a two-level
encryption design (header and payload), supporting extensions and
modifications of internal QUIC information to resist friction
from independent lower layers at deployment time.

However, it is of notoriety that the QUIC design is CPU costly. The root
cause of QUIC's high CPU cost isn't unique, and this document addresses
one of them: a misalignment between QUIC's protocol specification and
encryption usage. Indeed, the QUIC design in {{RFC9000}} unavoidably
fragments Application Data and forces any implementation to perform at
least a memory copy to provide a contiguous bytestream abstraction to
the upper layer, at the receiver.

This document suggests another QUIC Version demanding the Stream frame
to always be the first frame if any, and reversing the wire
representation of the QUIC protocol. These two changes offer the
opportunity for implementers to provide a contiguous zero-copy
abstraction at the receiver side for each stream using the decryption
internal copy for data reassembly. With this version, QUIC frames are
encoded in reverse ordering and would be processed from right to left at
the receiver, instead of the usual left to right as in any protocol. The
stream frame may be followed by any number of control frames up to the
packet boundary. Other stream frames may be packed within the same
packet, although receiver implementations would not be able to process
them in contiguous zero-copy.

# Goals

We aim to change how the QUIC protocol specifies its frames to support a
stream abstraction with the option to offer a contiguous zero-copy
interface to the upper layer. A few more bytes also have to be added
within the protected short header. Those changes are, however, engineered
with goals to:

- Minimize added control overheads.
- Incremental support is possible: minimal work for existing
implementations to migrate to this extension would need: 1) a change
within the packet header packetization logic, adding two variable
integers. The masking algorithm stays unchanged and maintains its
cryptographic properties. 2) The wire representation reverses field
ordering within frames. 3) a decrypted QUIC packet payload must be
processed at the receiver rewinding from the packet's last decrypted
byte to the first frame. Steps 2) and 3) should mirror existing code.
- Does not mandate existing QUIC implementations to support this
version. Can fallback to QUIC v1 (by the QUIC protocol negotiation
design).
- Does not modify any of the QUIC's transport properties (i.e., HoL
blocking avoidance, multiplexing, extensibility, ...) and does not
conflict with the goals of any ongoing work on QUIC extensions (e.g.,
MPQUIC) otherwise than by requiring them to change their wire
representation as well.
- Does not impact QUIC's security/safety assuming implementers follow
  added guidance to Reverso.
- Encryption/decryption stays compatible with the current usage of
existing crypto libraries.
- Implementations that have chosen a memory model to handle data
reassembly themselves and expose owned contiguous ranges of bytes in QUIC v1
can write a Reverso implementation without changing their Stream
reading API. Applications using these implementations may then receive a
QUIC update improving packet processing efficiency on negotiated QUIC
Reverso connections.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Streams {#Streams}

Stream ID values start at 1. We reserve the value 0 to indicate within
the new short header (see {{Header-Protection}}) that no stream frame is
packed within the encrypted payload.

# Frame Formats

Frames' structure written on the wire is altered in this QUIC version
to support a backward processing of QUIC packets. With the exception of
the ACK frame, all the other frames are straightforward to adapt from
{{RFC9000}}. Essentially, on {{RFC9000}}, each frame begins with a Frame
Type followed by additional type-dependent fields, and is represented
as this:

~~~
Frame {
  Frame Type (i),
  Type-Dependent Fields (..),
}
~~~

This representation follows the implicit rule that what we specify, from
top to bottom, is written and read from left to right on the wire.

If QUIC Reverso is used, frames are reversed. Type-dependent fields
appear first (from left to right on the wire), and the frame terminates
with the Frame Type. We represent those frames by reversing 
their representation in specifications:

~~~
Frame {
  Type-Dependent Fields (..),
  Frame Type (i),
}
~~~

The choice of order of Type-Dependent Fields only matters to ease
the transition and adaptation of existing code handling {{RFC9000}}'s frame
format. Reversing the existing ordering and not making other changes
within the relative order of elements may support straightforward
adaptation of existing code. For example, in {{RFC9000}}, the
MAX_STREAM_DATA Frame is defined as:

~~~
MAX_STREAM_DATA Frame {
  Type (i) = 0x11,
  Stream ID (i),
  Maximum Stream Data (i),
}
~~~

Which would translate to:

~~~
MAX_STREAM_DATA Frame {
  Maximum Stream Data (i),
  Stream ID (i),
  Type (i) = 0x11,
}
~~~

Other frames' wire format is altered with the same reversing logic. It includes
reversing internal structures in a given Frame if any, such as the ACK Frame.

## Frame format alternative to enable contiguous zero-copy receivers (to debate)

An alternative that does not reverse the control wire representation but
increases control overheads:

  - The stream frame header becomes a stream frame footer (i.e., appears
  after the data on the wire). Other control frames may appear after the
  stream frame is unchanged.
  - The offset of the stream frame footer has to be predicted by the
  receiver (possibly by adding another field to the short header, or
  another frame containing the offset value and the constraint that it
  must be located at the packet boundary).

This choice increases overheads in a QUIC packet (conflict with the goal
to minimize control overheads), but reduces implementation efforts in
regards to writing and processing reversed frames and back processing
the decrypted QUIC packet (inline with one of the initial goals to
minimize the cost of porting existing code to the new version).

Another alternative that has no more overhead and preserves most of
the current frames' field ordering would be to move the Type to the last
element of each frame on the wire, and backward process the packet on
the receiver. In the case of the Stream frame, all controls must be
written as a footer, the Type must be the last field, and the remaining
fields ordering may be preserved.

Note: The Ack frame structure depends on the direction of its processing
(assumed left-to-right). If the Ack Frame content is still processed in
this direction, the details below applied to the reversed ACK frame can be
ignored. If packets are processed from right-to-left (backward), below
details are relevant.

## Ack Frame's details

The Ack Frame is reversed as well, but requires further changes to the
ACK Range specifications and ECN Counts. The goal is to guarantee no
change in the processing logic of an ACK Frame, and minimal change to
existing code. Given back processing of a packet, the ACK Frame should
become:

~~~
ACK Frame {
  [ECN Counts (..)],
  ACK Range (..) ...,
  First ACK Range (i),
  ACK Range Count (i),
  ACK Dealy (i),
  Largest Acknowledged (i),
  Type (i)  = 0x02..0x03,
}
~~~

Where the ACK Range contains ranges of packets that are alternately not
acknowledged (Gap) and acknowledged (ACK Range). All other fields are
untouched; only their order on the wire is modified.

### Reversed ACK Ranges

In {{RFC9000}}, each ACK Range consists of alternating Gap and ACK Range
Length values *in descending packet number order* as appearing on the
wire. The ranges in {{RFC9000}} contain the information in reversed
ordering, starting from the largest acknowledged packets. In this
proposal, to accommodate backward processing of the frame and minimal
algorithmic changes, the ACK Range consists of alternating ACK Range
Length and Gap in *ascending packet number order*.

~~~
ACK Range {
  ACK Range Length (i),
  Gap (i),
}
~~~
{: #ack-range-format title="ACK Ranges"}

As explained in {{RFC9000}}, the fields that form each ACK Range are:

ACK Range Length:

: A variable-length integer indicating the number of contiguous acknowledged
  packets preceding the largest packet number, as determined by the
  last processed Gap.

Gap:

: A variable-length integer that represents the number of consecutive,
unacknowledged packets before the lowest-numbered packet in the last
processed acknowledgment range.

Since ACK Range Length and Gap are defined as relative integers; to keep
efficient processing and unchanged algorithmic compared to {{RFC9000}},
each ACK Range describes progressively lower-numbered packets while
being processed backwards. However, on the wire, from left to right,
each ACK Range describes progressively higher-numbered packets.

Therefore, while processing this information backwards, and given the
largest packet number for the current range, the smallest value is
determined by the following formula (like {{RFC9000}}):

~~~
   smallest = largest - ack_range
~~~

Where the largest value for an ACK Range is determined by cumulatively
subtracting the size of all preceding ACK Range Lengths and Gaps. The
first-largest value is obtained with the ACK Frame's Largest
Acknowledged field. The subsequent largest for each Ack Range is then
computed similarly to {{RFC9000}}:

~~~
   largest = previous_smallest - gap - 2
~~~

### Reversed ECN Counts

The ACK frame uses the least significant bit of the type value to
indicate ECN feedback. To facilitate minimal adjustments to the existing processing logic, the ECN Counts order is reversed in the ECN Counts order compared to {{RFC9000}}. This ensures that the order of processed elements remains the same.

~~~
ECN Counts {
  ECN-CE Count (i),
  ECT1 Count (i),
  ECT0 Count (i),
}
~~~
{: #ecn-count-format title="ECN Count Format"}

# Packet Formats {#Packet-Format}

For implementers to take advantage of Reverso and use the decryption
internal copy for data reassembly, we require to know the Stream ID of
any stream frame within the payload and the data offset.  These two
integers are added to the QUIC short header and protected with the mask
using a XOR. In QUIC v1,  5 out of 16 bytes available are being used. In
Reverso, we would use 13 out of 16 bytes.

## Header Protection {#Header-Protection}

The header of 1-RTT short header packets is extended to add at most 8 bytes
of information, requiring a 13-byte mask. Application of the mask
follows the same procedure as specified in {{RFC9001}}, as a minimum of
16 bytes are currently available from the current header protection
algorithms.

~~~
1-RTT Packet {
  Header Form (1) = 0,
  Fixed Bit (1) = 1,
  Spin Bit (1),
  Reserved Bits (2),         # Protected
  Key Phase (1),             # Protected
  Packet Number Length (2),  # Protected
  Destination Connection ID (0..160),
  Packet Number (8..32),     # Protected
  Stream ID (8..32)          # Protected
  Offset (8..32)             # Protected
  Protected Payload (0..72), # Skipped Part
  Protected Payload (128),   # Sampled Part
  Protected Payload (..),    # Remainder
}
~~~

The 1-RTT packets has the following modifications from QUIC v1:

- Packet Number: The Packet Number field is 1 to 4 bytes long, with the
least two significant bits of the last byte containing the length of the
Stream ID. This length is encoded as an unsigned two-bit integer that is
one less than the length of the Stream ID field in bytes. This field is protected using {{RFC9001}}’s mask, which can consume a maximum of 5 bytes (including the first header byte) from the minimum guaranteed 16 bytes.

- Stream ID: The Stream ID field is 1 to 4 bytes long, with the least
two significant bits of the last byte containing the length of the
Offset. This length is encoded as an unsigned two-bit integer that is
one less than the length of the Offset field in bytes. A 1-byte value of
0 for this field is reserved to indicate that the encrypted payload
does not contain any Stream frame. This field is protected using
{{RFC9001}}'s mask, up to consume 9 bytes from the minimum guaranteed 16
bytes in total.

- Offset: The Offset field is 1 to 4 bytes long, and encodes a value
based on the knowledge of the maximum acknowledged offset, similar to
the Packet Number field but encoding a value based on the highest
acknowledged offset. On the receiver, the decoding procedure is
similar to decoding packet numbers. This field is protected using
{{RFC9001}}'s mask, up to consume 13 bytes from the minimum guaranteed
16 bytes in total.

- Protected Payload Skipped Part's length: 72 bits are skipped instead
of 24. 24 bits are skipped in QUIC v1 to account for the maximum (yet
unknown) length of the Packet Number when sampling the encrypted payload
for header decryption. Since we add variable integers, we need sampling
further away to guarantee always falling into the AEAD encryption
(and/or tag). We need skipping 72 bits to account for the maximum
combined (yet unknown) lengths of Packet Number, Stream ID and offset.
This affects the minimum payload length for preparing a QUIC packet at
the sender, which was following the relation:

pn_len + min_payload_len + tag_len = 4 + sample_len

=> min_payload_len := 4 + sample_len - tag_len - pn_len
=> min_payload_len := 20 - tag_len - pn_len

for QUIC v1, defined in [RFC9001], where a safe static value can be set
to 3 bytes for min_payload_len (i.e., it is the max value of the upper
relation).  In VReverso, the relation becomes:

pn_len + stream_id_len + offset_len + min_payload_len + tag_len = 12 + sample_len

=> min_payload_len := 12 + sample_len - tag_len - pn_len - stream_id_len - offset_len
=> min_payload_len := 28 - tag_len - pn_len - stream_id_len - offset_len

A safe static value for min_payload_len can be set to 9 bytes in
implementations.

## Stream ID encoding (to debate)

The QUIC v1 protocol supports up to 2^{60} maximum streams. A QUIC
Reverso implementation must encode a Stream ID within at most 30 bits in
its header.  Due to the monotonic increasing nature of Stream IDs, we
can work out a solution that still permits up to 2^{60} maximum streams,
but constraints endpoints to fire at most 2^{30} new streams at any
time. We consider (up to debate) this constraint to exceed any
reasonable usage of the QUIC protocol given the memory requirement to
hold up to 2^{30} opened streams in memory. Different solutions are
possible.  An approach could be to reuse packet number
encoding/decoding, but based on acknowledged new streams.

## Frame ordering

In Reverso, a Stream Frame, if any, MUST be the first frame within the
payload. The Stream frame can be followed by any number of control
frames up to the packet boundary. Any other Stream frame SHOULD NOT be
added within the same QUIC packet, unless in scenarios where
multiplexing may bring more benefits than contiguous zero-copy (e.g.,
multiplexed HTTP queries within a single packet).

# Variable-Length Integer Encoding

QUIC v1 uses variable-length encoding for non-negative integer values to
encode fewer bytes on the wire than usual host representations. In QUIC
v1 the encoding reserves the two most significant bits of the first
byte, and encodes the integer in the remaining bits in the network byte
order. In this version, we encode the length in the two least
significant bits of the last byte to accommodate processing the
information by rewinding the buffer. The remaining bits encode the
integer value in the network byte order.

| 2LSB | Length | Usable Bits | Range                 |
|:-----|:-------|:------------|:----------------------|
| 00   | 1      | 6           | 0-63                  |
| 01   | 2      | 14          | 0-16383               |
| 10   | 4      | 30          | 0-1073741823          |
| 11   | 8      | 62          | 0-4611686018427387903 |
{: #integer-summary title="Summary of Integer Encodings with Reverso"}

# Security, Safety and Liveness Considerations

The goal of this section is to discuss careful considerations which a
QUIC Reverso implementation must consider while implementing a
contiguous zero-copy receiver interface.

## Avoiding Data Corruption

Contiguous zero-copy with Reverso is obtained by exploiting the added
information in the short header and the decryption's internal copy to
reassemble data fragments. For payload decryption, the Stream ID
contained within the short header should be used as a buffer selection
mechanism, and the offset is used to locate where to decrypt the packet
content within the buffer.

AEAD implementations may write at the destination address specified by
the caller even if the decryption fails. Therefore, receivers must track
the highest contiguous received authenticated offset for each stream and always
decrypt in place any packet containing an offset below or equal to the
tracked value.  Furthermore, implementers must be careful with data gaps
within a stream buffer created due to out-of-order packets, where the
decryption of a late out-of-order packet may override part of the
existing buffered data.

Different implementation solutions are possible to deal with this issue.
In all cases it involves a  copy of the decrypted data. A possible
solution is to apply the following logic:

if the packet's data is to be decrypted at a location higher than the
highest received contiguous offset + 1, and if the AEAD ciphertext is of
size N and aimed at location L in the stream buffer, check whether the
range L..L+N does not contain any previously decrypted data. Decrypt in
place if the answer is yes to avoid data corruption, and safely copy to
location L in the stream buffer.

## Manipulating Short Header bits may cause hitting Stream Limits

A QUIC Reverso implementation may allocate a new stream context before a
packet containing a new Stream is decrypted. If an on-path adversary
flips bits in the encrypted header it would result in a flipped bit in the
decrypted header as per {{RFC9001}}'s XOR properties used for header
protection. Such an event would be detected in the AEAD decryption phase,
since the AEAD decryption would fail. In the meantime, any memory
related to a new Stream context resulting from the adversarial
manipulation would need to be released, and stream limits would need to
be credited back.


--- back

# Acknowledgments {:numbered="false"}

TODO acknowledge.

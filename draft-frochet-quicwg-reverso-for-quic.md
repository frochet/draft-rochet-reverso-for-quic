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
  github: https://github.com/frochet/draft-rochet-reverso-generic

author:
 -
    fullname: Florentin Rochet
    organization: UNamur
    email: florentin.rochet@unamur.be

informative:
  RFC9000:
  RFC9001:

--- abstract

This document describes a QUIC extension re-designing the layout of the
QUIC protocol to avoid memory fragmentation at the receiver and allows
implementers seeking a more efficient implementation to have the option
to implement contiguous zero-copy at the receiver. This document
describes the change from QUIC v1 required in packet formats,
variable-length integers and frame formats. Everything else from QUIC
v1 described in {{RFC9000}} is untouched.

--- middle

# Introduction

# Goals

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Streams

Stream ID values start at 1. The value 0 is reserved to indicate within
the new short header (see {{Header-Protection}}) that no stream frame is
packed within the payload.

# Frame Formats

Frames' structure written on the wire are altered in this QUIC version
to support backward processing of QUIC packets. With the exception of
the ACK frame, all the other frames are straightforward to adapt from
{{RFC9000}}. Essentially, on {{RFC9000}}, each frame begins with a Frame
Type followed by additional type-dependent fields, and are represented
as this:

~~~
Frame {
  Frame Type (i),
  Type-Dependent Fields (..),
}
~~~

This representation follows the implicit rule that what we specify from
top to bottom is written and read from left to right on the wire.

If QUIC VReverso is used, frames are reversed. Type-dependent fields
appear first (from left to right on the wire), and the frame terminates
with the Frame Type. We represent those frames by reversing as well
their representation in specifications:

~~~
Frame {
  Type-Dependent Fields (..),
  Frame Type (i),
}
~~~

Of course, within an implementation, the relative order of elements
within Structs or Objects does not matter, and can stay untouched. Only
writting on wire and reading from the wire would be altered.

The choice of order of Type-Dependent Fields only matter to smooth
transition and adaptation of existing code handling {{RFC9000}}'s frame
format. Reversing the existing ordering, and not making other changes
within the relative order of elements supports straightforward
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

Other frames are altered with the same reversing logic. There is one
more step regarding the Ack Frame.

## Ack Frame's exception

The Ack Frame is reversed as well, but requires further changes on the
ACK Range's specification. The goal is to guarantee no change in
processing logic of a ACK Frame, and minimal change to existing code. We
have for this proposal the ACK Frame reversed:

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
untouched, only their order on the wire is modifierd.

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
  preceding Gap.

Gap:

: A variable-length integer indicating the number of contiguous unacknowledged
  packets preceding the packet number one lower than the smallest in the
  preceding ACK Range.

Since ACK Range Length and Gap are defined as relative integer; to keep
efficient processing, and unchanged algorithmic compared to {{RFC9000}},
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
first largest value is obtained with the ACK Frame's Largest
Acknowledged field. Subsequent largest for each Ack Range is then
computed similarly to {{RFC9000}}:

~~~
   largest = previous_smallest - gap - 2
~~~



# Packet Formats

For implementers to take advantage of Reverso, we require to know the
Stream ID of any stream frame within the payload, and the data offset.
These two integers are added in the QUIC short header and protected with
the mask.

## Header Protection {#Header-Protection}

Header of 1-RTT short header packets is extended to add at most 8 bytes
of information, requiring a 13-bytes mask. Application of the mask
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
  Protected Payload (0..24), # Skipped Part
  Protected Payload (128),   # Sampled Part
  Protected Payload (..),    # Remainder
}
~~~

The 1-RTT packets has the following modifications from QUIC v1:

- Packet Number: The Packet Number field is 1 to 4 bytes long with the
least significant two bits of the last byte containing the length of the
Stream ID. This length is encoded as an unsigned two-bit integer that is
one less than the length of the Stream ID field in bytes. This is field
is protected using {{RFC9001}}'s mask up to consume 5 bytes (including
the header's first byte) from the minimum guaranteed 16 bytes in total.

- Stream ID: The Stream ID field is 1 to 4 bytes long with the least
significant two bits of the last byte containing the length of the
Offset. This is length is encoded as an unsigned two-bit integer that is
one less than the length of the Offset field in bytes. A 1-byte value of
0 for the this field is reserved to indicate that the encrypted payload
does not contain any Stream frame. This field is protected using
{{RFC9001}}'s mask, up to consume 9 bytes from the minimum guaranteed 16
bytes in total.

- Offset: The Offset field is 1 to 4 bytes long, and encodes a value
based on the knowledge of the maximum acknowledged offset, similarly to
the Packet Number field encoding a value based on the maximum
acknowledged packet number. On the receiver, the decoding procedure is
similar to decoding packet numbers. This field is protected using
{{RFC9001}}'s mask, up to consume 13 bytes from the minimum guaranteed
16 bytes in total.

## Frame ordering

In Reverso, a Stream Frame, if any, MUST be the first frame within the
payload. The Stream frame can be followed by any number of control
frames up to the packet boundary. Any other Stream frame SHOULD NOT be
added within the same QUIC packet.

# Variable-Length Integer Encoding

QUIC v1 uses variable-length encoding for non-negative integer values to
encode fewer bytes on the wire than usual host representations. In QUIC
v1 the encoding reserves the two most significant bits of the first
byte, and encode the integer in the remaining bits, in network byte
order. In this version, we encode the length in the two least
significant bits of the last byte to accommodate processing the
information by rewinding the buffer. The remaining bits encode the
integer value in network byte order.

| 2LSB | Length | Usable Bits | Range                 |
|:-----|:-------|:------------|:----------------------|
| 00   | 1      | 6           | 0-63                  |
| 01   | 2      | 14          | 0-16383               |
| 10   | 4      | 30          | 0-1073741823          |
| 11   | 8      | 62          | 0-4611686018427387903 |
{: #integer-summary title="Summary of Integer Encodings with Reverso"}

# Reversing to enable contiguous zero-copy

There is a straightforward protocol design adaptation that could be
applied to any encrypted protocol to enable transport implementers to go
for a contiguous zero-copy interface if wished. This proposal does not
relax any security guarantee of the protocol, nor obliges a transport
implementer to change its interface to application while supporting the
new version.

- First, we require to reverse the order of the fields within all
encrypted control chunks. That is, if a chunk is defined by:



~~~
struct {
  type (8),
  foo (16),
  bar (8..16),
}
~~~

and is written on the wire from left to right starting at `type`, then
chunk MUST be written starting from `bar` up to `type`. For clarity, we
suggest that any protocol design applying Reverso reverses as well
their field presentation. Such struct would become:

~~~
struct {
  bar (8..16),
  foo (16),
  type (8),
}
~~~

- Second, the order and number of data chunks within a single encryption
matters. The data chunk MUST be the first element within the encryption,
followed by any number of control chunks, up to the packet boundary. We
SHOULD pack a single data chunk per encryption. More than one would
create fragments on the receiver, and increase the cost of message
reassembly by forcing an unavoidable memory copy to deliver a contiguous
stream of bytes.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

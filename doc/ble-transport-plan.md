# BLE transport (`fi.refineid.rapp.ble`)

The requester opens RAPP sessions to the paired phone over Bluetooth Low
Energy GATT when the local network finds no phone. It runs on FreeBSD
only; on every other system the BLE path is absent and behavior is the
stream tier's alone. Pairing stays on the stream tier: both phone
applications refuse a pairing preamble over BLE.

Normative sources: RAPP v26.11.2 sections 2.2, 4.1, 5.1 to 5.3 and 8.3,
and the transport and discovery hierarchy specification section 3, in
refineid-core `doc/protocols/`; Bluetooth Core Specification v5.4 Vol 3
Part F (ATT), Part G (GATT), Vol 4 Part E (HCI).

## What runs

Each search round (`crates/refineid-rapp-core/src/remote.rs`) browses and
dials the stream tier first. When no stream service opened a session in
that round, one BLE scan of 2 seconds runs, and the connectable
advertisers whose advertising data or scan response lists the RAPP
service UUID are dialed strongest RSSI first. Each connection carries a
fresh `rapp-ble` session routing value; a phone that does not hold the
pairing closes the link and the next one is tried. A phone's close
reason, a protocol violation, and an absent card end the search as on
the stream tier. No BLE address is kept past the round.

A connection is GATT over the fixed ATT channel, not an L2CAP
connection-oriented channel:

1. ATT MTU exchange asking for 515; below 512 the link drops.
2. Discover All Primary Services, the RAPP service's characteristics,
   and the Channel Characteristic's CCCD. The channel must declare Write
   and Indicate and the bootstrap Read; Extended Properties is allowed
   (iOS adds it), any other bit is refused.
3. Write `0x0002` to the CCCD.
4. The routing preamble as a SAR `SINGLE`, then the `Noise_KK` session.

Frames travel as SAR messages (`refineid_rapp::ble_sar`): Write Requests
from the requester, each awaiting its Write Response; indications from
the phone, each confirmed at once, reassembled within 5 seconds. Every
ATT request the phone sends is answered at once with an Error Response
(the requester runs no GATT server), and indications on other handles
are confirmed and dropped.

## Code

`crates/refineid-rapp-core/src/ble/`:

- `att.rs`: the ATT PDUs, typed at the wire border.
- `gatt.rs`: the connection setup over an `AttBearer`.
- `advertising.rs`, `hci.rs`: LE Advertising Reports and the bounded scan
  over an `HciChannel`; scanning is disabled however the scan ends.
- `transport.rs`: `BleFrameTransport`, the RAPP frame transport.
- `freebsd/`: the raw HCI and L2CAP sockets; `freebsd/sys.rs` holds the
  only unsafe code.

All but `freebsd/` is platform-neutral and tested on synthetic bytes.

## Prerequisites

A normal user scans and connects once root has set the adapter up; the
commands are in [install-freebsd.md](install-freebsd.md), section 3.
RefineID does not run them. The adapter is the first USB one,
`ubt0hci`.

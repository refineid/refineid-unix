// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! RAPP frames over a set-up GATT link (RAPP v26.11.8 sections 5.2 and
//! 5.3): each frame is one SAR message, sent as Write Requests on the
//! Channel Characteristic, each awaiting its Write Response, and received
//! as indications, each confirmed, reassembled within 5 seconds of its
//! first fragment.
//!
//! The link carries no identity: the routing preamble only selects a
//! pairing, and `Noise_KK` authenticates the session on top (section
//! 2.2.1).

use std::time::{Duration, Instant};

use refineid_rapp::ble_sar::{
    BLE_SAR_REASSEMBLY_TIMEOUT_MS, BleSarError, BleSarReassembler, payload_capacity, segment,
};
use refineid_rapp::{
    BLE_CANDIDATE_ID, BLE_PROFILE, BinaryFrame, PreambleError, RoutingPreamble, TransportProfile,
};

use super::gatt::{AttBearer, GattError, GattLink};
use crate::limits;
use crate::transport::{FrameTransport, TransportError};

/// How long a frame may take to reassemble after its first fragment.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_millis(BLE_SAR_REASSEMBLY_TIMEOUT_MS);

/// Why a BLE connection did not reach the session phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BleOpenError {
    /// The GATT setup of section 5.2 failed.
    Setup(GattError),
    /// The negotiated MTU leaves no SAR capacity.
    Capacity(BleSarError),
    /// The routing preamble did not encode.
    Preamble(PreambleError),
    /// The routing preamble was not delivered.
    Routing(TransportError),
}

/// The transport profile `fi.refineid.rapp.ble` over one GATT link.
#[derive(Debug)]
pub struct BleFrameTransport<B> {
    link: GattLink<B>,
    capacity: usize,
    reassembler: BleSarReassembler,
    frame_started: Option<Instant>,
    epoch: Instant,
    receive_deadline: Duration,
}

impl<B: AttBearer> BleFrameTransport<B> {
    /// Sets up the RAPP channel on `bearer` by `setup_deadline` and sends
    /// `preamble` as its first frame, a SAR `SINGLE` (section 5.2 item 3).
    ///
    /// # Errors
    /// [`BleOpenError`] for every failure; the connection drops with it.
    pub fn open(
        bearer: B,
        preamble: &RoutingPreamble,
        receive_deadline: Duration,
        setup_deadline: Instant,
    ) -> Result<Self, BleOpenError> {
        let preamble = preamble
            .encode(TransportProfile::Ble)
            .map_err(BleOpenError::Preamble)?;
        let link = GattLink::set_up(bearer, setup_deadline).map_err(BleOpenError::Setup)?;
        let capacity =
            payload_capacity(link.mtu().octets(), None).map_err(BleOpenError::Capacity)?;
        let mut transport = Self {
            link,
            capacity,
            reassembler: BleSarReassembler::new(),
            frame_started: None,
            epoch: Instant::now(),
            receive_deadline,
        };
        transport
            .send_frame(&preamble)
            .map_err(BleOpenError::Routing)?;
        Ok(transport)
    }

    /// Milliseconds since this transport opened, the reassembler's clock.
    fn clock_ms(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.epoch).as_millis()).unwrap_or(u64::MAX)
    }

    /// The failure a mid-frame interruption is: the frame is lost.
    fn abandon(&mut self) -> TransportError {
        self.reassembler.reset();
        self.frame_started = None;
        TransportError::Failed
    }
}

impl<B: AttBearer> FrameTransport for BleFrameTransport<B> {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.is_empty() || frame.len() > limits::NOISE_MAX_MESSAGE {
            return Err(TransportError::OversizedFrame);
        }
        let fragments = segment(frame, self.capacity).map_err(|_| TransportError::Failed)?;
        for fragment in fragments {
            self.link
                .write_channel(&fragment)
                .map_err(|_| TransportError::Failed)?;
        }
        Ok(())
    }

    fn receive_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        let deadline = Instant::now() + self.receive_deadline;
        loop {
            let wait_until = self.frame_started.map_or(deadline, |started| {
                deadline.min(started + REASSEMBLY_TIMEOUT)
            });
            match self.link.next_channel_indication(wait_until) {
                Ok(indication) => {
                    let arrived = self.clock_ms(indication.arrived);
                    match self
                        .reassembler
                        .receive(&indication.fragment, self.capacity, arrived)
                    {
                        Ok(Some(frame)) => {
                            self.frame_started = None;
                            return Ok(frame);
                        }
                        Ok(None) => {
                            self.frame_started.get_or_insert(indication.arrived);
                        }
                        Err(_) => return Err(self.abandon()),
                    }
                }
                Err(GattError::TimedOut) if self.frame_started.is_none() => {
                    return Err(TransportError::TimedOut);
                }
                Err(GattError::Closed) if self.frame_started.is_none() => {
                    return Err(TransportError::Eof);
                }
                Err(_) => return Err(self.abandon()),
            }
        }
    }

    fn set_receive_deadline(&mut self, deadline: Duration) -> Result<Duration, TransportError> {
        Ok(core::mem::replace(&mut self.receive_deadline, deadline))
    }

    fn profile(&self) -> &str {
        BLE_PROFILE
    }

    fn candidate_id(&self) -> &str {
        BLE_CANDIDATE_ID
    }
}

impl<B: AttBearer> refineid_rapp::FrameTransport for BleFrameTransport<B> {
    type Error = TransportError;

    fn candidate_id(&self) -> &str {
        BLE_CANDIDATE_ID
    }

    fn send(&mut self, frame: BinaryFrame) -> Result<(), Self::Error> {
        self.send_frame(frame.as_bytes())
    }

    fn receive(&mut self) -> Result<Option<BinaryFrame>, Self::Error> {
        match self.receive_frame() {
            Ok(bytes) => {
                let frame =
                    BinaryFrame::reconstruct(bytes).map_err(|_| TransportError::OversizedFrame)?;
                Ok(Some(frame))
            }
            Err(TransportError::Eof) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The link closes when the transport, and with it the bearer, drops.
    fn close(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::time::{Duration, Instant};

    use refineid_rapp::ble_sar::{payload_capacity, segment};
    use refineid_rapp::{RoutingPreamble, SessionRouting, TransportProfile};

    use super::super::att::{self, REQUESTED_ATT_MTU, fixtures};
    use super::super::gatt::script::{self, CHANNEL_VALUE, ScriptedBearer, Step};
    use super::{BleFrameTransport, BleOpenError};
    use crate::transport::{FrameTransport, TransportError};

    /// How long a test receive waits.
    const DEADLINE: Duration = Duration::from_millis(50);
    /// A synthetic frame that takes several fragments.
    const LONG_FRAME_REPEAT: usize = 300;
    /// A synthetic session routing value: the preamble's content does not
    /// matter to the transport.
    const ROUTING: &[u8] = b"synthetic routing value of 32 b.";

    fn preamble() -> RoutingPreamble {
        RoutingPreamble::Session(SessionRouting::from_bytes(ROUTING).unwrap())
    }

    fn capacity() -> usize {
        payload_capacity(usize::from(REQUESTED_ATT_MTU), None).unwrap()
    }

    fn writes(frame: &[u8]) -> Vec<Step> {
        segment(frame, capacity())
            .unwrap()
            .into_iter()
            .flat_map(|fragment| {
                [
                    Step::Sent(att::write_request(
                        fixtures::handle(CHANNEL_VALUE),
                        &fragment,
                    )),
                    Step::Peer(fixtures::write_response()),
                ]
            })
            .collect()
    }

    fn indications(frame: &[u8]) -> Vec<Step> {
        segment(frame, capacity())
            .unwrap()
            .into_iter()
            .flat_map(|fragment| {
                [
                    Step::Peer(fixtures::indication(CHANNEL_VALUE, &fragment)),
                    Step::Sent(att::handle_value_confirmation()),
                ]
            })
            .collect()
    }

    fn opened(rest: Vec<Step>) -> Result<BleFrameTransport<ScriptedBearer>, BleOpenError> {
        let mut steps = script::setup();
        steps.extend(writes(&preamble().encode(TransportProfile::Ble).unwrap()));
        steps.extend(rest);
        BleFrameTransport::open(
            ScriptedBearer::new(steps),
            &preamble(),
            DEADLINE,
            Instant::now() + DEADLINE,
        )
    }

    #[test]
    fn frames_move_both_ways_in_fragments() {
        let long = b"frame".repeat(LONG_FRAME_REPEAT);
        let mut steps = writes(&long);
        steps.extend(indications(&long));
        let mut transport = opened(steps).unwrap();
        transport.send_frame(&long).unwrap();
        assert_eq!(transport.receive_frame().unwrap(), long);
    }

    #[test]
    fn a_refused_routing_fails_the_open() {
        let mut steps = script::setup();
        steps.push(Step::Close);
        let opened = BleFrameTransport::open(
            ScriptedBearer::new(steps),
            &preamble(),
            DEADLINE,
            Instant::now() + DEADLINE,
        );
        assert_eq!(
            opened.err(),
            Some(BleOpenError::Routing(TransportError::Failed))
        );
    }

    #[test]
    fn quiet_is_timed_out_and_a_close_between_frames_is_eof() {
        let mut transport = opened(vec![Step::Silence, Step::Close]).unwrap();
        assert_eq!(transport.receive_frame(), Err(TransportError::TimedOut));
        assert_eq!(transport.receive_frame(), Err(TransportError::Eof));
    }

    #[test]
    fn a_close_inside_a_frame_fails() {
        let long = b"frame".repeat(LONG_FRAME_REPEAT);
        let mut steps: Vec<Step> = indications(&long).into_iter().take(2).collect();
        steps.push(Step::Close);
        let mut transport = opened(steps).unwrap();
        assert_eq!(transport.receive_frame(), Err(TransportError::Failed));
    }

    #[test]
    fn a_fragment_the_sar_layer_refuses_fails() {
        let mut transport = opened(vec![
            Step::Peer(fixtures::indication(CHANNEL_VALUE, b"short")),
            Step::Sent(att::handle_value_confirmation()),
        ])
        .unwrap();
        assert_eq!(transport.receive_frame(), Err(TransportError::Failed));
    }

    #[test]
    fn the_transport_names_the_ble_profile() {
        let transport = opened(Vec::new()).unwrap();
        assert_eq!(transport.profile(), refineid_rapp::BLE_PROFILE);
        assert_eq!(
            FrameTransport::candidate_id(&transport),
            refineid_rapp::BLE_CANDIDATE_ID
        );
    }
}

//! This computer's view of its paired phone: the
//! `requester_view_of_custodian` machine of RAPP v26.11.2 section 4.7 and
//! its state model, for a program that keeps a session open while the
//! phone is in sight (section 8.3).
//!
//! The view decides when to dial and nothing else. A dial follows only the
//! phone's appearance, a local consumer's request, or a redial due within
//! the redial window after a loss (section 8.3, cross-component rule X-07);
//! none follows while the phone is withdrawn (INV-16). How a session ended
//! moves the view as section 4.5 item 6 says. The view is never shown:
//! the user sees only the card it offers (section 4.7).

use std::time::{Duration, Instant};

use refineid_rapp::{REDIAL_WINDOW_MS, RequesterSessionEnd};

/// The redial window after a loss or a failed dial (section 8.3 item 3).
const REDIAL_WINDOW: Duration = Duration::from_millis(REDIAL_WINDOW_MS);

/// The first back-off of the redial window.
const FIRST_REDIAL_PAUSE: Duration = Duration::from_secs(1);

/// The longest back-off of the redial window.
const LONGEST_REDIAL_PAUSE: Duration = Duration::from_secs(16);

/// Where the view of the paired phone stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewState {
    /// No session and no redial window: a dial follows only the phone's
    /// appearance or a consumer's request.
    Idle,
    /// A dial is being set up, or is due on the back-off within the redial
    /// window.
    Connecting,
    /// A session is open.
    Connected,
    /// The phone withdrew, or can serve no card: nothing is dialed or
    /// offered until it announces itself again.
    Withdrawn,
}

/// What a local consumer's request for the card meets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumerAnswer {
    /// Dial for it.
    Dial,
    /// Answer at once that no remote card is available.
    Refuse,
}

/// The view of the paired phone, with what it last saw of it.
#[derive(Debug)]
pub struct CustodianView {
    state: ViewState,
    /// The service instances in sight at the last look.
    sight: Vec<String>,
    /// When the redial window opened, while one runs.
    window_opened: Option<Instant>,
    /// When the next redial is due, while the window runs.
    next_dial: Option<Instant>,
    /// The back-off before the next redial.
    pause: Duration,
}

impl Default for CustodianView {
    fn default() -> Self {
        Self::new()
    }
}

impl CustodianView {
    /// A view in [`ViewState::Idle`] that has seen nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ViewState::Idle,
            sight: Vec::new(),
            window_opened: None,
            next_dial: None,
            pause: FIRST_REDIAL_PAUSE,
        }
    }

    /// Where the view stands.
    #[must_use]
    pub const fn state(&self) -> ViewState {
        self.state
    }

    /// One look saw the phone's session records under `instances`.
    /// Returns whether the phone appeared: an instance in sight that was
    /// not at the last look, which is a first sight, a fresh instance name
    /// or a return after vanishing (section 8.3). An appearance in
    /// [`ViewState::Idle`] or [`ViewState::Withdrawn`] moves the view to
    /// [`ViewState::Connecting`]: dial now.
    pub fn looked(&mut self, instances: Vec<String>) -> bool {
        let appeared = instances
            .iter()
            .any(|instance| !self.sight.contains(instance));
        self.sight = instances;
        if appeared && self.state != ViewState::Connected {
            self.state = ViewState::Connecting;
        }
        appeared && self.state == ViewState::Connecting
    }

    /// A look matched the phone's withdrawn record (section 4.5 item 6):
    /// a dial being set up is dropped and the view withdraws, unless a
    /// session is open, which outranks discovery.
    pub fn withdrawal_seen(&mut self) {
        self.sight.clear();
        if self.state != ViewState::Connected {
            self.end_window();
            self.state = ViewState::Withdrawn;
        }
    }

    /// A local consumer asks for the card with no session open.
    pub fn consumer_request(&mut self) -> ConsumerAnswer {
        match self.state {
            ViewState::Withdrawn => ConsumerAnswer::Refuse,
            ViewState::Idle | ViewState::Connecting | ViewState::Connected => {
                if self.state == ViewState::Idle {
                    self.state = ViewState::Connecting;
                }
                ConsumerAnswer::Dial
            }
        }
    }

    /// Whether a redial is due at `now` within the redial window. A window
    /// that ran out with no dial running moves the view to
    /// [`ViewState::Idle`].
    pub fn redial_due(&mut self, now: Instant) -> bool {
        if self.state != ViewState::Connecting {
            return false;
        }
        let Some(opened) = self.window_opened else {
            return false;
        };
        if now.saturating_duration_since(opened) >= REDIAL_WINDOW {
            self.end_window();
            self.state = ViewState::Idle;
            return false;
        }
        self.next_dial.is_some_and(|due| now >= due)
    }

    /// A dial reached `session.ready`.
    pub fn dial_succeeded(&mut self) {
        self.end_window();
        self.state = ViewState::Connected;
    }

    /// A dial ended before `session.ready` at `now`: the redial window
    /// opens with the first failed dial since the phone last appeared, and
    /// the next redial is scheduled within it; once it has passed the view
    /// is [`ViewState::Idle`].
    pub fn dial_failed(&mut self, now: Instant) {
        if self.state != ViewState::Connecting {
            return;
        }
        let opened = *self.window_opened.get_or_insert(now);
        if now.saturating_duration_since(opened) >= REDIAL_WINDOW {
            self.end_window();
            self.state = ViewState::Idle;
        } else {
            self.schedule_redial(now);
        }
    }

    /// The session or the dial ended as `end` says, at `now` (section 4.5
    /// item 6). A revocation and a withdrawal drop the view to
    /// [`ViewState::Withdrawn`], the caller forgetting the pairing for a
    /// revocation; a violation to [`ViewState::Idle`] with no redial; a
    /// loss opens the redial window at once.
    pub fn session_ended(&mut self, end: RequesterSessionEnd, now: Instant) {
        self.end_window();
        match end {
            RequesterSessionEnd::Revoked | RequesterSessionEnd::Withdrawn => {
                self.state = ViewState::Withdrawn;
            }
            RequesterSessionEnd::Violation => self.state = ViewState::Idle,
            RequesterSessionEnd::Loss => {
                self.state = ViewState::Connecting;
                self.window_opened = Some(now);
                self.schedule_redial(now);
            }
        }
    }

    /// This computer closed the session for its own reasons: no redial
    /// window opens, and the next dial follows an appearance or a
    /// consumer's request.
    pub fn closed_here(&mut self) {
        self.end_window();
        self.state = ViewState::Idle;
    }

    /// The next redial after the current back-off, which doubles up to
    /// its longest.
    fn schedule_redial(&mut self, now: Instant) {
        self.next_dial = Some(now + self.pause);
        self.pause = self.pause.saturating_mul(2).min(LONGEST_REDIAL_PAUSE);
    }

    /// No redial window runs.
    fn end_window(&mut self) {
        self.window_opened = None;
        self.next_dial = None;
        self.pause = FIRST_REDIAL_PAUSE;
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use refineid_rapp::RequesterSessionEnd;

    use super::{ConsumerAnswer, CustodianView, FIRST_REDIAL_PAUSE, REDIAL_WINDOW, ViewState};

    /// A synthetic service instance.
    const INSTANCE: &str = "custodian-1";
    /// A fresh instance name of the same phone.
    const FRESH_INSTANCE: &str = "custodian-2";

    fn sight(instances: &[&str]) -> Vec<String> {
        instances.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn an_idle_view_dials_only_on_an_appearance_or_a_request() {
        let mut view = CustodianView::new();
        let now = Instant::now();
        assert!(!view.redial_due(now));
        assert!(view.looked(sight(&[INSTANCE])));
        assert_eq!(view.state(), ViewState::Connecting);
        view.dial_succeeded();
        view.session_ended(RequesterSessionEnd::Violation, now);
        assert_eq!(view.state(), ViewState::Idle);
        assert!(
            !view.looked(sight(&[INSTANCE])),
            "still in sight: no appearance"
        );
        assert!(
            !view.redial_due(now + REDIAL_WINDOW),
            "a violation opens no window"
        );
        assert_eq!(view.consumer_request(), ConsumerAnswer::Dial);
        assert_eq!(view.state(), ViewState::Connecting);
    }

    #[test]
    fn a_loss_redials_within_the_window_and_then_waits() {
        let mut view = CustodianView::new();
        let lost = Instant::now();
        view.looked(sight(&[INSTANCE]));
        view.dial_succeeded();
        view.session_ended(RequesterSessionEnd::Loss, lost);
        assert_eq!(view.state(), ViewState::Connecting);
        assert!(!view.redial_due(lost));
        assert!(view.redial_due(lost + FIRST_REDIAL_PAUSE));
        view.dial_failed(lost + FIRST_REDIAL_PAUSE);
        assert!(!view.redial_due(lost + FIRST_REDIAL_PAUSE));
        assert!(!view.redial_due(lost + REDIAL_WINDOW + Duration::from_millis(1)));
        assert_eq!(view.state(), ViewState::Idle);
    }

    #[test]
    fn a_withdrawal_dials_nothing_until_the_phone_announces_itself_again() {
        let mut view = CustodianView::new();
        let now = Instant::now();
        view.looked(sight(&[INSTANCE]));
        view.dial_succeeded();
        view.session_ended(RequesterSessionEnd::Withdrawn, now);
        assert_eq!(view.state(), ViewState::Withdrawn);
        assert_eq!(view.consumer_request(), ConsumerAnswer::Refuse);
        assert!(!view.redial_due(now + FIRST_REDIAL_PAUSE));
        assert!(
            !view.looked(sight(&[INSTANCE])),
            "an advertisement already in sight"
        );
        assert!(view.looked(sight(&[INSTANCE, FRESH_INSTANCE])));
        assert_eq!(view.state(), ViewState::Connecting);
    }

    #[test]
    fn a_withdrawn_record_drops_a_dial_but_not_an_open_session() {
        let mut view = CustodianView::new();
        view.looked(sight(&[INSTANCE]));
        view.withdrawal_seen();
        assert_eq!(view.state(), ViewState::Withdrawn);
        assert!(view.looked(sight(&[INSTANCE])), "back after vanishing");
        view.dial_succeeded();
        view.withdrawal_seen();
        assert_eq!(view.state(), ViewState::Connected);
    }

    #[test]
    fn a_failed_dial_opens_the_window_once() {
        let mut view = CustodianView::new();
        let first = Instant::now();
        view.looked(sight(&[INSTANCE]));
        view.dial_failed(first);
        assert_eq!(view.state(), ViewState::Connecting);
        assert!(view.redial_due(first + FIRST_REDIAL_PAUSE));
        view.dial_failed(first + REDIAL_WINDOW);
        assert_eq!(view.state(), ViewState::Idle);
    }
}

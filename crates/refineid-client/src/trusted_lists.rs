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

//! The EU trusted lists over this computer's cache and HTTP stack.
//!
//! Fetching, storing, refreshing and anchoring live in
//! [`refineid_doc_sign::verification::trusted_list::cache`]; this
//! module is the Unix edge around it: the per-user cache directory,
//! this crate's HTTP transport, the first download's progress on
//! standard error, and the background refresh the GUI starts.

use std::ffi::OsString;
use std::io::{IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::thread::JoinHandle;

pub use refineid_doc_sign::verification::trusted_list::cache::{
    AnchorSource, FINNISH_TERRITORY, FinnishListGap, ListCache, Refresh, RunAnchors,
    certificate_issuing_ders,
};
use refineid_doc_sign::verification::trusted_list::cache::{
    CacheEvent, prefetching_get, run_anchors,
};
use refineid_doc_sign::verification::trusted_list::{fetch_over_http, lotl_signers};
use refineid_doc_sign::x509::DateTime;

/// The XDG base-directory cache variable.
const XDG_CACHE_HOME: &str = "XDG_CACHE_HOME";
/// The home directory variable.
const HOME: &str = "HOME";
/// The cache directory under a home directory.
const CACHE_DIRECTORY: &str = ".cache";
/// The application's directory under the cache directory.
const APPLICATION_DIRECTORY: &str = "refineid";
/// The lists' directory under the application's.
const LISTS_DIRECTORY: &str = "trusted-lists";

/// The per-user cache: `$XDG_CACHE_HOME/refineid/trusted-lists`,
/// or `$HOME/.cache/refineid/trusted-lists`. Returns `None` for a
/// privileged process (root or setuid/setgid) so inherited caller
/// environment variables cannot steer writes into a caller-chosen
/// directory, or when no variable names an absolute directory.
fn user_cache() -> Option<ListCache> {
    user_cache_for(crate::ca_certificates::process_is_privileged(), |name| {
        std::env::var_os(name).filter(|value| !value.is_empty())
    })
}

/// [`user_cache`] parameterised on privilege status and environment lookup
/// for unit tests.
fn user_cache_for(
    privileged: bool,
    variable: impl Fn(&str) -> Option<OsString>,
) -> Option<ListCache> {
    if privileged {
        return None;
    }
    directory_from(variable).map(ListCache::at)
}

/// [`user_cache`] over the environment `variable` reads.
fn directory_from(variable: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let absolute = |name: &str| {
        variable(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let cache = absolute(XDG_CACHE_HOME)
        .or_else(|| absolute(HOME).map(|home| home.join(CACHE_DIRECTORY)))?;
    Some(cache.join(APPLICATION_DIRECTORY).join(LISTS_DIRECTORY))
}

/// Held by every run over the user's cache in this process that may
/// fetch, so a background fetch ([`fetch_in_background`]) and a run
/// that needs the lists meanwhile fetch them once: the later run
/// waits, then reads what the first stored. A [`Refresh::CacheOnly`]
/// run, the GUI's card readout, never waits: every file is replaced
/// by an atomic rename, so it reads whole lists, old or new.
static USER_CACHE: Mutex<()> = Mutex::new(());

/// [`run_anchors`] over the user's cache, the Official Journal's
/// list-signing certificates core ships and this crate's HTTP
/// transport, one fetching run at a time in this process. The first
/// download into an empty cache shows its progress on standard error
/// when that is a terminal. Diagnostics go to the CLI log.
#[must_use]
pub fn user_anchors(now: DateTime, refresh: Refresh) -> RunAnchors {
    user_anchors_shown(now, refresh, std::io::stderr().is_terminal())
}

/// [`user_anchors`], the first download's progress shown when
/// `terminal` says standard error is one.
fn user_anchors_shown(now: DateTime, refresh: Refresh, terminal: bool) -> RunAnchors {
    let _one_at_a_time = (refresh != Refresh::CacheOnly)
        .then(|| USER_CACHE.lock().unwrap_or_else(PoisonError::into_inner));
    crate::doc_sign_http::install();
    let signers = lotl_signers();
    let cache = user_cache();
    let progress = DownloadProgress {
        shown: terminal
            && refresh != Refresh::CacheOnly
            && cache.as_ref().is_none_or(ListCache::holds_no_list),
    };
    let mut report = |event: CacheEvent| match event {
        CacheEvent::CachedListsUnreadable { error } => {
            refineid_dev_errors::report!(Cli, "cached trusted lists not read", error);
        }
        CacheEvent::ListsNotCached { error } => {
            refineid_dev_errors::report!(Cli, "trusted lists not cached", error);
        }
        CacheEvent::ListsNotFetched { error } => {
            refineid_dev_errors::report!(Cli, "trusted lists not fetched", error);
        }
        CacheEvent::AttemptNotRecorded { error } => {
            refineid_dev_errors::report!(Cli, "trusted-list fetch time not recorded", error);
        }
    };
    let run = run_anchors(
        cache.as_ref(),
        now,
        refresh,
        &signers,
        prefetching_get(&signers, fetch_over_http, &|fetched, total| {
            progress.fetched(fetched, total);
        }),
        &mut report,
    );
    progress.end();
    run
}

/// What the label of the first download's progress line says.
const PROGRESS_LABEL: &str = "Fetching the EU trusted lists: ";
/// Between the lists fetched and the lists to fetch.
const PROGRESS_OF: &str = "/";
/// Erase in Line from the cursor to its end (ECMA-48 section 8.3.41,
/// `EL` with the default parameter).
const ERASE_LINE: &str = "\x1b[K";

/// The first download's progress: one line on standard error counting
/// the national lists fetched, erased when the download ends, so a
/// command stays silent on success. A later refresh shows nothing; it
/// replaces lists already at hand.
struct DownloadProgress {
    /// Whether the line is shown.
    shown: bool,
}

impl DownloadProgress {
    /// Show that `fetched` of `total` national lists arrived.
    fn fetched(&self, fetched: usize, total: usize) {
        if self.shown {
            let mut stderr = std::io::stderr().lock();
            let _shown = write!(stderr, "\r{PROGRESS_LABEL}{fetched}{PROGRESS_OF}{total}")
                .and_then(|()| stderr.flush());
        }
    }

    /// Erase the line.
    fn end(&self) {
        if self.shown {
            let mut stderr = std::io::stderr().lock();
            let _erased = write!(stderr, "\r{ERASE_LINE}").and_then(|()| stderr.flush());
        }
    }
}

/// Bring the user's lists up to date on a thread of their own when a
/// fetch is due ([`Refresh::WhenDue`]), so that the first signing or
/// verification after an install, or after the cache went stale, finds
/// them at hand instead of waiting for the download. A run that needs
/// the lists before the thread is done waits for it and fetches
/// nothing again.
pub fn fetch_in_background() -> JoinHandle<()> {
    std::thread::spawn(|| {
        let _run = user_anchors_shown(refineid_doc_sign::now_date_time(), Refresh::WhenDue, false);
    })
}

#[cfg(test)]
mod tests;

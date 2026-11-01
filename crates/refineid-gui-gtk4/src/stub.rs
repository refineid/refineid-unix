// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! macOS stub for GTK 4 presentation driver.
//!
//! macOS uses native Apple AppKit/Swift (`refineid-apple`). GTK 4 is not
//! targeted on macOS.

use std::sync::Arc;

use refineid_gui_core::controller::RefineIdController;
use refineid_gui_core::driver::UiDriver;
use refineid_gui_core::error::GuiCoreError;
use refineid_gui_core::model::UiState;

/// Type alias for state update callback closure.
pub type StateChangeCallback = Box<dyn Fn(&UiState) + Send + Sync + 'static>;

/// GTK 4 presentation driver stub for macOS.
#[derive(Copy, Clone, Debug, Default)]
pub struct Gtk4Driver;

impl Gtk4Driver {
    /// Create driver stub.
    pub fn create() -> (Self, StateChangeCallback) {
        (Self, Box::new(|_| {}))
    }
}

impl UiDriver for Gtk4Driver {
    fn init(&mut self) -> Result<(), GuiCoreError> {
        Ok(())
    }

    fn render(&mut self, _state: &UiState) {}

    fn run(self, _controller: Arc<RefineIdController>) -> Result<(), GuiCoreError> {
        eprintln!(
            "RefineID GTK 4 driver is supported on FreeBSD and Linux. On macOS, use native RefineID (refineid-apple) or FLTK."
        );
        Ok(())
    }
}

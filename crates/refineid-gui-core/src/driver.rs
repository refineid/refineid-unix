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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Presentation driver trait definition.

use std::sync::Arc;

use crate::controller::RefineIdController;
use crate::error::GuiCoreError;
use crate::model::UiState;

/// Presentation driver interface implemented by GUI toolkits (FLTK, GTK 4, etc.).
///
/// The driver is purely responsible for presentation and input dispatch:
/// it receives immutable [`UiState`] updates from the controller, renders them,
/// and dispatches [`UserIntent`](crate::model::UserIntent) actions back to the controller.
pub trait UiDriver: Sized + 'static {
    /// Initialize toolkit resources, window, and layouts.
    fn init(&mut self) -> Result<(), GuiCoreError>;

    /// Apply an updated state snapshot to the UI controls.
    fn render(&mut self, state: &UiState);

    /// Enter the toolkit event loop and run until window exit.
    fn run(self, controller: Arc<RefineIdController>) -> Result<(), GuiCoreError>;
}

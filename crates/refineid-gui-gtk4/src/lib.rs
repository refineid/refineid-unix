// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! GTK 4 presentation driver for RefineID.

#[cfg(not(target_os = "macos"))]
pub mod driver;

#[cfg(not(target_os = "macos"))]
pub use driver::Gtk4Driver;

#[cfg(target_os = "macos")]
pub mod stub;

#[cfg(target_os = "macos")]
pub use stub::Gtk4Driver;

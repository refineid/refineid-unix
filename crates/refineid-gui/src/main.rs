// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! Portable desktop application for FINEID card management.
//!
//! Presentation drivers:
//! - GTK 4 (`--driver gtk4`): Tier 1 modern desktop driver.
//! - FLTK (`--driver fltk`): Tier 2 lightweight/minimalist driver.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(any(feature = "gtk4", feature = "fltk"))]
use refineid_gui_core::controller::RefineIdController;
#[cfg(any(feature = "gtk4", feature = "fltk"))]
use refineid_gui_core::driver::UiDriver;

#[cfg(not(any(feature = "gtk4", feature = "fltk")))]
compile_error!(
    "At least one presentation driver feature ('gtk4' or 'fltk') must be enabled for refineid-gui."
);

/// Starts the controller; `--pair` turns remote use on, which shows the
/// pairing prompt while no phone is paired.
#[cfg(any(feature = "gtk4", feature = "fltk"))]
fn start_controller(
    on_state_change: impl Fn(&refineid_gui_core::model::UiState) + Send + Sync + 'static,
    pair: bool,
) -> std::sync::Arc<RefineIdController> {
    let controller = RefineIdController::new(on_state_change);
    controller.start();
    if pair {
        controller.handle_intent(refineid_gui_core::model::UserIntent::SetRemoteUse(true));
    }
    controller
}

#[cfg(feature = "fltk")]
fn run_fltk(pair: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (driver, on_state_change) = refineid_gui_fltk::FltkDriver::create();
    driver.run(start_controller(on_state_change, pair))?;
    Ok(())
}

#[cfg(feature = "gtk4")]
fn run_gtk4(pair: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (driver, on_state_change) = refineid_gui_gtk4::Gtk4Driver::create();
    driver.run(start_controller(on_state_change, pair))?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut explicit_driver = None;
    let mut pair = false;

    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--pair" {
            pair = true;
            continue;
        }
        if arg == "--driver" {
            if let Some(val) = iter.next() {
                explicit_driver = Some(val.as_str());
            }
            continue;
        }
        if let Some(val) = arg.strip_prefix("--driver=") {
            explicit_driver = Some(val);
            continue;
        }
        if !arg.starts_with('-') {
            explicit_driver = Some(arg.as_str());
        }
    }

    #[cfg(feature = "gtk4")]
    let default_driver = "gtk4";

    #[cfg(all(feature = "fltk", not(feature = "gtk4")))]
    let default_driver = "fltk";

    #[cfg(not(any(feature = "gtk4", feature = "fltk")))]
    let default_driver = "none";

    let chosen = explicit_driver.unwrap_or(default_driver);

    let available: &[&str] = &[
        #[cfg(feature = "gtk4")]
        "gtk4",
        #[cfg(feature = "fltk")]
        "fltk",
    ];
    let available_str = available.join(", ");

    let ran = match chosen {
        #[cfg(feature = "gtk4")]
        "gtk4" => run_gtk4(pair),
        #[cfg(feature = "fltk")]
        "fltk" => run_fltk(pair),
        other => {
            eprintln!(
                "Unknown or unsupported presentation driver: '{other}' (available: {available_str})"
            );
            std::process::exit(2);
        }
    };
    refineid_dev_errors::flush!();
    ran
}

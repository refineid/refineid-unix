// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! Portable desktop application for FINEID card management.
//!
//! Presentation drivers:
//! - GTK 4 (`--driver gtk4`): Tier 1 modern desktop driver with Apple HIG styling.
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

#[cfg(feature = "fltk")]
fn run_fltk(initial_tab: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, on_state_change) = refineid_gui_fltk::FltkDriver::create();
    if initial_tab == Some("phone") {
        driver.open_on_phone_tab();
    }
    let controller = RefineIdController::new(on_state_change);
    controller.start();
    driver.run(controller)?;
    Ok(())
}

#[cfg(feature = "gtk4")]
fn run_gtk4(initial_tab: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, on_state_change) = refineid_gui_gtk4::Gtk4Driver::create();
    if let Some(tab) = initial_tab {
        driver.set_initial_tab(tab);
    }
    let controller = RefineIdController::new(on_state_change);
    controller.start();
    driver.run(controller)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut explicit_driver = None;
    let mut initial_tab = None;

    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--pair" {
            initial_tab = Some("phone");
            continue;
        }
        if arg == "--tab" {
            if let Some(val) = iter.next() {
                initial_tab = Some(val.as_str());
            }
            continue;
        }
        if let Some(val) = arg.strip_prefix("--tab=") {
            initial_tab = Some(val);
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
        "gtk4" => run_gtk4(initial_tab),
        #[cfg(feature = "fltk")]
        "fltk" => run_fltk(initial_tab),
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

// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! Portable desktop application for FINEID card management.
//!
//! The presentation driver is selected with `--driver fltk|gtk4` (default:
//! `fltk`; set `default = ["gtk4"]` for Linux desktop builds).

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use refineid_gui_core::controller::RefineIdController;
use refineid_gui_core::driver::UiDriver;

#[cfg(feature = "fltk")]
fn run_fltk(open_on_phone_tab: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, on_state_change) = refineid_gui_fltk::FltkDriver::create();
    if open_on_phone_tab {
        driver.open_on_phone_tab();
    }
    let controller = RefineIdController::new(on_state_change);
    controller.start();
    driver.run(controller)?;
    Ok(())
}

#[cfg(feature = "gtk4")]
fn run_gtk4(open_on_phone_tab: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (mut driver, on_state_change) = refineid_gui_gtk4::Gtk4Driver::create();
    if open_on_phone_tab {
        driver.open_on_phone_tab();
    }
    let controller = RefineIdController::new(on_state_change);
    controller.start();
    driver.run(controller)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let driver_name = args.get(1).map(|s| s.as_str()).unwrap_or("fltk");
    let open_on_phone = args.iter().any(|a| a == "--pair");

    match driver_name {
        #[cfg(feature = "gtk4")]
        "gtk4" => run_gtk4(open_on_phone),
        #[cfg(feature = "fltk")]
        "fltk" => run_fltk(open_on_phone),
        _ => {
            eprintln!("unknown driver: {driver_name} (use fltk or gtk4)");
            std::process::exit(2);
        }
    }
}

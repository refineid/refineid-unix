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

//! Links the libraries FLTK needs on FreeBSD.
//!
//! On FreeBSD fltk-sys builds FLTK with its Wayland backend and the GTK 3
//! libdecor plugin, but links their libraries only under its
//! `use-wayland` feature, which is a Linux-only build switch. Only the
//! binaries that link this crate get them: GTK 3 in a GTK 4 binary binds
//! `gtk_init_check` to GTK 3's.

use std::process::Command;

/// The libraries FLTK's Wayland backend and its GTK 3 libdecor plugin call.
const FREEBSD_LIBRARIES: &[&str] = &[
    "wayland-client",
    "wayland-cursor",
    "wayland-egl",
    "xkbcommon",
    "dbus-1",
    "EGL",
    "GL",
    "gtk-3",
    "gdk-3",
    "gobject-2.0",
    "glib-2.0",
    "gio-2.0",
    "pango-1.0",
    "pangocairo-1.0",
    "cairo",
];

/// Where FreeBSD packages install their libraries.
const FREEBSD_LIBRARY_DIRECTORY: &str = "/usr/local/lib";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("freebsd") {
        return;
    }
    println!("cargo:rustc-link-search=native={FREEBSD_LIBRARY_DIRECTORY}");
    for library in FREEBSD_LIBRARIES {
        println!("cargo:rustc-link-lib=dylib={library}");
    }
    // FLTK uses the system libdecor when one is installed and its bundled
    // copy otherwise.
    let system_libdecor = Command::new("pkg-config")
        .args(["--exists", "libdecor-0"])
        .status()
        .is_ok_and(|status| status.success());
    if system_libdecor {
        println!("cargo:rustc-link-lib=dylib=decor-0");
    }
}

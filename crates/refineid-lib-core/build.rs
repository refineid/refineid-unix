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

//! Sets `REFINEID_VERSION`, the project version: `YY.M.D.B`, or
//! `YY.M.D~MB` when the build mark `M` is set. `YY.M.D` is the package
//! version, `B` the build number (`REFINEID_BUILD_NUMBER` when set, else
//! the UTC time of day of this build) and `M` is `REFINEID_BUILD_MARK`.

use std::env;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

include!("src/build_number.rs");

const BUILD_NUMBER_ENV: &str = "REFINEID_BUILD_NUMBER";
const BUILD_MARK_ENV: &str = "REFINEID_BUILD_MARK";
const PACKAGE_VERSION_ENV: &str = "CARGO_PKG_VERSION";
const VERSION_ENV: &str = "REFINEID_VERSION";
/// A path that never exists. Cargo reruns a build script on every
/// build while a `rerun-if-changed` path is missing, so the build
/// number is the time of the latest build.
const ALWAYS_RERUN: &str = "refineid-build-number-always-rerun";

fn main() -> ExitCode {
    println!("cargo:rerun-if-changed={ALWAYS_RERUN}");
    let build = match env::var(BUILD_NUMBER_ENV) {
        Ok(build) if is_build_number(&build) => build,
        Ok(build) => {
            eprintln!("error: {BUILD_NUMBER_ENV}={build:?} is not hour * 100 + minute");
            return ExitCode::FAILURE;
        }
        Err(_) => match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => build_number(elapsed.as_secs()).to_string(),
            Err(_) => {
                eprintln!("error: system clock is before 1970");
                return ExitCode::FAILURE;
            }
        },
    };
    let mark = match env::var(BUILD_MARK_ENV) {
        Ok(mark) if is_build_mark(&mark) => Some(mark),
        Ok(mark) => {
            eprintln!("error: {BUILD_MARK_ENV}={mark:?} is not a word of letters a-z");
            return ExitCode::FAILURE;
        }
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            eprintln!("error: {BUILD_MARK_ENV} is not a word of letters a-z");
            return ExitCode::FAILURE;
        }
    };
    let Ok(day) = env::var(PACKAGE_VERSION_ENV) else {
        eprintln!("error: {PACKAGE_VERSION_ENV} is not set");
        return ExitCode::FAILURE;
    };
    let version = project_version(&day, mark.as_deref(), &build);
    println!("cargo:rustc-env={VERSION_ENV}={version}");
    ExitCode::SUCCESS
}

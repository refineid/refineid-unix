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

//! Sets `REFINEID_BUILD_NUMBER`, the build number `B` of the project
//! version `YY.M.D.B`: the override of the same name when set, else the
//! UTC time of day of this build.

use std::env;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

include!("src/build_number.rs");

const BUILD_NUMBER_ENV: &str = "REFINEID_BUILD_NUMBER";
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
    println!("cargo:rustc-env={BUILD_NUMBER_ENV}={build}");
    ExitCode::SUCCESS
}

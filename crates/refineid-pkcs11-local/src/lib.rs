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

//! Local-reader-only PKCS#11 v2.40 module for FINEID: local readers through
//! `refineid-core` without remote phone source or pairing store access.
//!
//! Intended for PAM card-login services (`pam_pkcs11`) including unprivileged
//! screen lockers (such as KDE Plasma 6's `kscreenlocker_greet`), ensuring they
//! never touch the user's pairing store, open remote network sockets, or dial a phone.

use refineid_pkcs11::ck::{CkFunctionListPtrPtr, CkRv};

/// The one symbol a PKCS#11 host resolves by name (OASIS PKCS#11 v2.40
/// s5.6.4). Unlike `refineid_pkcs11`, this module never installs a phone
/// source.
///
/// # Safety
/// `list` must be a valid, writable location for one
/// `CK_FUNCTION_LIST_PTR`, per the PKCS#11 caller contract.
#[allow(
    unsafe_code,
    reason = "the exported symbol and the forward to the core entry point are the module's one FFI boundary"
)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn C_GetFunctionList(list: CkFunctionListPtrPtr) -> CkRv {
    // SAFETY: `list` validity is the caller's PKCS#11 contract; the
    // core entry point null-checks it before writing.
    unsafe { refineid_pkcs11::get_function_list(list) }
}

#[cfg(test)]
#[allow(unsafe_code, reason = "FFI call to C_GetFunctionList")]
mod tests {
    use super::*;
    use refineid_pkcs11::ck::CkFunctionListPtr;

    #[test]
    fn function_list_resolves_and_has_entry_points() {
        let mut list: CkFunctionListPtr = core::ptr::null_mut();
        let rv = unsafe { C_GetFunctionList(&raw mut list) };
        assert_eq!(rv, 0);
        assert!(!list.is_null());
        let functions = unsafe { *list };
        assert_eq!(functions.version.major, 2);
    }
}

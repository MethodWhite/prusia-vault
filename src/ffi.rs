//! FFI bindings for prusia-vault
use crate::Vault;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;

/// Create a new PQC vault instance
#[no_mangle]
pub extern "C" fn prusia_vault_new_pqc(data_dir: *const c_char) -> *mut Vault {
    let c_str = unsafe { CStr::from_ptr(data_dir) };
    let dir = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let vault = Vault::pqc(PathBuf::from(dir));
    Box::into_raw(Box::new(vault))
}

/// Initialize vault with passphrase
#[no_mangle]
pub extern "C" fn prusia_vault_initialize(vault: *mut Vault, passphrase: *const c_char) -> i32 {
    let vault = unsafe { &mut *vault };
    let c_str = unsafe { CStr::from_ptr(passphrase) };
    let pass = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match vault.initialize(pass) {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

/// Store a secret in the vault
#[no_mangle]
pub extern "C" fn prusia_vault_store_secret(
    vault: *mut Vault,
    key: *const c_char,
    value: *const c_char,
) -> i32 {
    let vault = unsafe { &mut *vault };
    let c_key = unsafe { CStr::from_ptr(key) };
    let c_val = unsafe { CStr::from_ptr(value) };

    let key_str = match c_key.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let val_str = match c_val.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match vault.store(key_str, val_str) {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

/// Retrieve a secret from the vault
#[no_mangle]
pub extern "C" fn prusia_vault_retrieve_secret(
    vault: *const Vault,
    key: *const c_char,
) -> *mut c_char {
    let vault = unsafe { &*vault };
    let c_key = unsafe { CStr::from_ptr(key) };

    let key_str = match c_key.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match vault.retrieve(key_str) {
        Ok(val) => {
            let c_str = CString::new(val).unwrap();
            c_str.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a C-string allocated by the vault
#[no_mangle]
pub extern "C" fn prusia_vault_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Execute a WASM module within the vault
#[no_mangle]
pub extern "C" fn prusia_vault_execute_wasm(
    vault: *mut Vault,
    _module_ptr: *const u8,
    _module_len: usize,
) -> i32 {
    let _vault = unsafe { &mut *vault };
    // Placeholder for WASM execution logic
    // In a real implementation, this would use a crate like wasmi
    debug_assert!(!_module_ptr.is_null());
    0 // Return success for now
}

/// Emergency wipe of all vault data
#[no_mangle]
pub extern "C" fn prusia_vault_emergency_wipe(vault: *mut Vault) -> i32 {
    let vault = unsafe { &mut *vault };
    match vault.wipe() {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Free a vault instance
#[no_mangle]
pub extern "C" fn prusia_vault_free(vault: *mut Vault) {
    if !vault.is_null() {
        unsafe {
            let _ = Box::from_raw(vault);
        }
    }
}

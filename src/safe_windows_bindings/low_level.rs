use std::ffi::c_void;
use std::io::Error;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, SECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL,
    TOKEN_ACCESS_MASK, TOKEN_INFORMATION_CLASS, TOKEN_TYPE,
};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};

/// Closes a token and returns an error if there was one
pub fn close_token(h_object: HANDLE) -> Result<(), String> {
    // Close the token
    let closed = unsafe { CloseHandle(h_object).as_bool() };
    // If it couldn't be closed, find out why and return the error
    if !closed {
        let last_error = Error::last_os_error();
        return Err(format!("Unable to close handle: {last_error}"));
    }
    Ok(())
}

/// Gets a handle to a process using specific pid and access rights
pub fn open_process(
    dw_desired_access: PROCESS_ACCESS_RIGHTS,
    b_inherit_handle: bool,
    pid: u32,
) -> Result<HANDLE, String> {
    // Open the process
    let process_handle = unsafe { OpenProcess(dw_desired_access, b_inherit_handle, pid) };
    // Format error case
    process_handle.map_err(|err| format!("Could not obtain process: {err}"))
}

/// Gets the token of a process using its handle and desired access
///
/// Closes the provided process handle in any case
pub fn open_process_token(
    process_handle: HANDLE,
    desired_access: TOKEN_ACCESS_MASK,
) -> Result<HANDLE, String> {
    // Create empty token handle
    let mut token_handle: HANDLE = HANDLE::default();
    // Fill it with the process token
    let success =
        unsafe { OpenProcessToken(process_handle, desired_access, &mut token_handle).as_bool() };
    // If it couldn't be opened, close the empty token handle and the process handle and return
    if !success {
        let mut errors: Vec<String> = Vec::new();
        let last_error = Error::last_os_error();
        errors.push(format!("Unable to open process token: {last_error}"));
        if let Err(err) = close_token(process_handle) {
            errors.push(err);
        }
        if let Err(err) = close_token(token_handle) {
            errors.push(err);
        }
        let errors_combined = errors.join("\n");
        return Err(errors_combined);
    }

    // If it could be opened close the process handle anyway
    close_token(process_handle)?;

    // Return the token handle
    Ok(token_handle)
}

/// Duplicates a token
///
/// Closes the initial token handle in any case
pub fn duplicate_token_ex(
    h_existing_token: HANDLE,
    dw_desired_access: TOKEN_ACCESS_MASK,
    lp_token_attributes: Option<*const SECURITY_ATTRIBUTES>,
    impersonation_level: SECURITY_IMPERSONATION_LEVEL,
    token_type: TOKEN_TYPE,
) -> Result<HANDLE, String> {
    // Create empty token handle
    let mut ph_new_token = HANDLE::default();

    // Attempt duplication
    let duplicated = unsafe {
        DuplicateTokenEx(
            h_existing_token,
            dw_desired_access,
            lp_token_attributes,
            impersonation_level,
            token_type,
            &mut ph_new_token,
        )
        .as_bool()
    };

    // On failure close all provides handles
    if !duplicated {
        let mut errors: Vec<String> = Vec::new();
        let last_error = Error::last_os_error();
        errors.push(format!("Unable to duplicate token: {last_error}"));
        if let Err(err) = close_token(h_existing_token) {
            errors.push(err);
        }
        if let Err(err) = close_token(ph_new_token) {
            errors.push(err);
        }
        let errors_combined = errors.join("\n");
        return Err(errors_combined);
    }

    // On success close the first token and return the new duplicated one
    close_token(h_existing_token)?;
    Ok(ph_new_token)
}

/// Safe binding to a windows api version of the function
pub fn wts_get_active_console_session_id() -> u32 {
    unsafe { WTSGetActiveConsoleSessionId() }
}

/// Get the current user token
pub fn wts_query_user_token(session_id: u32) -> Result<HANDLE, String> {
    // Create empty token handle
    let mut token_handle = HANDLE::default();

    // Obtain the user token
    let success = unsafe { WTSQueryUserToken(session_id, &mut token_handle).as_bool() };

    // Close it on failure
    if !success {
        let mut errors: Vec<String> = Vec::new();
        let last_error = Error::last_os_error();
        errors.push(format!(
            "Unable to obtain current user handle: {last_error}"
        ));
        if let Err(err) = close_token(token_handle) {
            errors.push(err);
        }
        let errors_combined = errors.join("\n");
        return Err(errors_combined);
    }

    Ok(token_handle)
}

/// Safe binding to a windows api version of the function
pub fn get_token_information(
    token: HANDLE,
    token_information_class: TOKEN_INFORMATION_CLASS,
    token_information: Option<*mut c_void>,
    token_information_length: u32,
    return_length: &mut u32,
) -> Result<(), String> {
    let success = unsafe {
        GetTokenInformation(
            token,
            token_information_class,
            token_information,
            token_information_length,
            return_length,
        )
        .as_bool()
    };

    let mut errors: Vec<String> = Vec::new();

    if !success {
        let last_error = Error::last_os_error();
        errors.push(format!("Unable to get token information: {last_error}"));
    }

    if let Err(err) = close_token(token) {
        errors.push(err);
    }

    if !errors.is_empty() {
        let errors_combined = errors.join("\n");
        return Err(errors_combined);
    }

    Ok(())
}

/// Safe binding to a windows api version of the function
#[allow(clippy::too_many_arguments)]
pub fn create_process_as_user_w(
    token: HANDLE,
    application_name: PCWSTR,
    command_line: PWSTR,
    process_attributes: Option<*const SECURITY_ATTRIBUTES>,
    thread_attributes: Option<*const SECURITY_ATTRIBUTES>,
    inherit_handle: bool,
    creation_flags: PROCESS_CREATION_FLAGS,
    environment: Option<*const c_void>,
    current_directory: PCWSTR,
    startup_info: STARTUPINFOW,
    mut process_information: PROCESS_INFORMATION,
) -> Result<(), String> {
    let created = unsafe {
        CreateProcessAsUserW(
            token,
            application_name,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handle,
            creation_flags,
            environment,
            current_directory,
            &startup_info,
            &mut process_information,
        )
        .as_bool()
    };

    let mut errors: Vec<String> = Vec::new();

    if !created {
        let last_error = Error::last_os_error();
        errors.push(format!("Unable to create process: {last_error}"));
        return Err(format!("Unable to create process: {last_error}"));
    }

    let mut errors: Vec<String> = Vec::new();

    if let Err(err) = close_token(process_information.hThread) {
        errors.push(err);
    };
    if let Err(err) = close_token(process_information.hProcess) {
        errors.push(err);
    };
    if let Err(err) = close_token(token) {
        errors.push(err);
    }

    if !errors.is_empty() {
        let errors_combined = errors.join("\n");
        return Err(errors_combined);
    }

    Ok(())
}

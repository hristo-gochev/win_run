use crate::safe_windows_bindings::low_level::{
    create_process_as_user_w, duplicate_token_ex, get_token_information, open_process,
    open_process_token, wts_get_active_console_session_id, wts_query_user_token,
};
use std::os::raw::c_void;
use sysinfo::{PidExt, Process, ProcessExt, System, SystemExt};
use widestring::U16CString;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    SecurityImpersonation, TokenLinkedToken, TokenPrimary, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_LINKED_TOKEN, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, STARTUPINFOW,
};

/// Gets the pid of a process by name
pub fn get_process_pid(process_name: &str) -> Result<u32, String> {
    let system = System::new_all();
    let processes: Vec<&Process> = system.processes_by_name(process_name).collect();
    let process_pid = processes.first().map(|process| process.pid().as_u32());
    match process_pid {
        None => Err(format!("No running processes by the name: {process_name}")),
        Some(process_pid) => Ok(process_pid),
    }
}

/// Gets the token of a process by pid
pub fn get_process_token(pid: u32) -> Result<HANDLE, String> {
    // Get the process handle by pid
    let process_handle = open_process(PROCESS_QUERY_INFORMATION, false, pid)?;

    // Specify access rights
    let desired_access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;

    // Get the token of the process
    let process_token_handle = open_process_token(process_handle, desired_access)?;

    // Duplicate the token
    let duplicated_token_handle = duplicate_token_ex(
        process_token_handle,
        desired_access,
        None,
        SecurityImpersonation,
        TokenPrimary,
    )?;

    // Return the duplicated token
    Ok(duplicated_token_handle)
}

/// Gets the current user token
pub fn get_current_user_token() -> Result<HANDLE, String> {
    // Get the active session id
    let active_session_id = wts_get_active_console_session_id();

    // Get the current user token
    let current_user_token = wts_query_user_token(active_session_id)?;

    // Specify access rights
    let access_flags = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;

    // Duplicate the token and return it
    duplicate_token_ex(
        current_user_token,
        access_flags,
        None,
        SecurityImpersonation,
        TokenPrimary,
    )
}

/// Adds admin rights to a token handle
pub fn add_admin_privileges_to_token(token: HANDLE) -> Result<HANDLE, String> {
    // Windows api magic
    let token_information_class = TokenLinkedToken;
    let mut token_linked: TOKEN_LINKED_TOKEN = unsafe { std::mem::zeroed() };
    let token_information = Some(((&mut token_linked) as *mut TOKEN_LINKED_TOKEN) as *mut c_void);
    let token_information_length = std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32;
    let mut return_length = 0u32;

    // Magic elevation
    if let Err(err) = get_token_information(
        token,
        token_information_class,
        token_information,
        token_information_length,
        &mut return_length,
    ) {
        return Err(format!("Could not elevate process token: {err}"));
    }

    Ok(token_linked.LinkedToken)
}

/// Starts a process with specified settings
pub fn create_process_with_token(
    token: HANDLE,
    application_name: &str,
    command_line: &str,
    current_directory: &str,
    desktop: &str,
) -> Result<(), String> {
    // Convert all parameters to their native versions
    let application_name = U16CString::from_str(application_name)
        .map_err(|err| format!("Cannot convert string to U16CString: {err}"))?;
    let application_name = PCWSTR::from_raw(application_name.as_ptr());

    let mut command_line = U16CString::from_str(command_line)
        .map_err(|err| format!("Cannot convert string to U16CString: {err}"))?;
    let command_line = PWSTR::from_raw(command_line.as_mut_ptr());

    let current_directory = U16CString::from_str(current_directory)
        .map_err(|err| format!("Cannot convert string to U16CString: {err}"))?;
    let current_directory = PCWSTR::from_raw(current_directory.as_ptr());

    let mut lp_desktop = U16CString::from_str(desktop)
        .map_err(|err| format!("Cannot convert string to U16CString: {err}"))?;
    let lp_desktop = PWSTR::from_raw(lp_desktop.as_mut_ptr());

    // Create the startup info
    let mut startup_info = STARTUPINFOW::default();
    startup_info.cb = std::mem::size_of_val(&startup_info) as u32;
    startup_info.lpDesktop = lp_desktop;

    // Create the process information
    let process_information = PROCESS_INFORMATION::default();

    let mut errors: Vec<String> = Vec::new();

    // Attempt starting
    if let Err(err) = create_process_as_user_w(
        token,
        application_name,
        command_line,
        None,
        None,
        false,
        PROCESS_CREATION_FLAGS(0),
        None,
        current_directory,
        startup_info,
        process_information,
    ) {
        errors.push(err);
    }

    // On error format the errors and return
    if !errors.is_empty() {
        let errors_combined = errors.join("\n");
        return Err(errors_combined);
    }

    Ok(())
}

/*!
Crate `win_run` allows Windows Services to run any executable as User, Admin or Local System.

# Important
In order for any of the functions offered by the library to work they must be executed from a Windows Service!

# Usage
To use this crate, add `win_run` as a dependency to your project's `Cargo.toml`:
```toml
[dependencies]
win_run = "0.1.0"
```

# Example: Start a process as Admin on the Default desktop:
```
use win_run::{Desktop, Elevation, run};

run("/executable/path", "args", "/current/directory/", Desktop::Default, Elevation::Admin)?;
```

# Example: Start a process as Local System on the Secure desktop:
```
use win_run::{Desktop, Elevation, run};

run("/executable/path", "args", "/current/directory/", Desktop::Secure, Elevation::LocalSystem)?;
```
 */

mod safe_windows_bindings;

use crate::safe_windows_bindings::high_level::{
    add_admin_privileges_to_token, create_process_with_token, get_current_user_token,
    get_process_pid, get_process_token,
};

pub enum Elevation {
    User,
    Admin,
    LocalSystem,
}

pub enum Desktop {
    Default,
    Secure,
}

/// Runs an executable with specified access rights and settings
///
/// # Arguments
///
/// * `path` - The path to the executable.
/// * `args` - Arguments with which to execute.
/// * `directory` - Directory from which to run the executable.
/// * `desktop` - Desktop on which the executable should run.
/// * `elevation` - User as which to run the executable.
pub fn run(
    path: &str,
    args: &str,
    directory: &str,
    desktop: Desktop,
    elevation: Elevation,
) -> Result<(), String> {
    let application_name = path;

    let command_line = format!("{path} {args}");

    let current_directory = directory;

    let desktop = match desktop {
        Desktop::Default => "",
        Desktop::Secure => "WinSta0\\Winlogon",
    };

    let token = match elevation {
        Elevation::User => get_current_user_token()?,
        Elevation::Admin => {
            let mut current_user_token = get_current_user_token()?;
            current_user_token = add_admin_privileges_to_token(current_user_token)?;
            current_user_token
        }
        Elevation::LocalSystem => {
            let process_pid = get_process_pid("winlogon")?;
            get_process_token(process_pid)?
        }
    };

    create_process_with_token(
        token,
        application_name,
        &command_line,
        current_directory,
        desktop,
    )
}

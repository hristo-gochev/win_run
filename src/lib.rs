/*!
Crate `win_run` allows Windows Services to run any executable as User, Admin or Local System.

# Important
In order for any of the functions offered by the library to work they must be executed from a Windows Service!

# Usage
To use this crate, add `win_run` as a dependency to your project's `Cargo.toml`:
```toml
[dependencies]
win_run = "0.2.0"
```

# Example: Start a process as Admin on the Default desktop:
```
use win_run::{Desktop, Elevation, win};

win("/path/to/executable")
    .args("-flag")
    .directory("/parent/directory")
    .desktop(Desktop::Default)
    .elevation(Elevation::Admin)
    .run()?;
```

# Example: Start a process as Local System on the Secure desktop:
```
use win_run::{Desktop, Elevation, win};

win("/path/to/executable")
    .args("-flag")
    .directory("/parent/directory")
    .desktop(Desktop::Secure)
    .elevation(Elevation::LocalSystem)
    .run()?;
```
 */

mod safe_windows_bindings;

use crate::safe_windows_bindings::high_level::{
    add_admin_privileges_to_token, create_process_with_token, get_current_user_token,
    get_process_pid, get_process_token,
};

#[derive(Default)]
pub enum Elevation {
    #[default]
    User,
    Admin,
    LocalSystem,
}

#[derive(Default)]
pub enum Desktop {
    #[default]
    Default,
    Secure,
}

/// Creates a process builder with default settings
///
/// # Arguments
///
/// * `path` - Path to an executable.
pub fn win(path: impl AsRef<str>) -> ProcessBuilder {
    ProcessBuilder::new(path)
}

/// Utility process builder
pub struct ProcessBuilder {
    /// The path to the executable
    pub(crate) path: String,
    /// Arguments with which to execute.
    pub(crate) args: String,
    /// Directory from which to run the executable
    pub(crate) directory: String,
    /// Desktop on which the executable should run
    pub(crate) desktop: Desktop,
    /// User as which to run the executable
    pub(crate) elevation: Elevation,
}

impl ProcessBuilder {
    /// Initialized a new process builder
    pub fn new(path: impl AsRef<str>) -> Self {
        let path = path.as_ref().to_string();
        let args = "".to_owned();
        let directory = std::env::current_exe()
            .expect("Could not get path to the current executable")
            .parent()
            .expect("Could not get path to the directory of the current executable")
            .to_str()
            .expect("Could not get the current directory path as utf-8")
            .to_string();
        let desktop = Desktop::default();
        let elevation = Elevation::default();

        Self {
            path,
            args,
            directory,
            desktop,
            elevation,
        }
    }

    /// Sets the arguments with which to run the executable, default is **empty string**
    pub fn args(mut self, args: impl AsRef<str>) -> Self {
        self.args = args.as_ref().to_string();
        self
    }

    /// Sets the directory from which to run the executable, default is **std::env::current_exe().parent()**
    pub fn directory(mut self, directory: impl AsRef<str>) -> Self {
        self.directory = directory.as_ref().to_string();
        self
    }

    /// Sets the desktop on which the executable should run, default is **Desktop::Default**
    pub fn desktop(mut self, desktop: Desktop) -> Self {
        self.desktop = desktop;
        self
    }

    /// Sets the user as which to run the executable, default is **Elevation::User**
    pub fn elevation(mut self, elevation: Elevation) -> Self {
        self.elevation = elevation;
        self
    }

    /// Runs the built process
    pub fn run(&self) -> Result<(), String> {
        let application_name = &self.path;

        let command_line = format!("{} {}", self.path, self.args);

        let current_directory = &self.directory;

        let desktop = match self.desktop {
            Desktop::Default => "",
            Desktop::Secure => "WinSta0\\Winlogon",
        };

        let token = match self.elevation {
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
}

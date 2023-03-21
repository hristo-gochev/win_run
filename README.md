# win_run
Run any executable as User, Admin or Local System from a Windows Service.

### Usage

To use this crate, add `win_run` as a dependency to your project's `Cargo.toml`:

```toml
[dependencies]
win_run = "0.2.0"
```

### Important
In order for any of the functions offered by the library to work they must be run from a Windows Service!

### Examples

Start a process as Admin on the Default desktop:

```rust,no_run
use win_run::{Desktop, Elevation, win};

win("/path/to/executable")
    .args("-flag")
    .directory("/parent/directory")
    .desktop(Desktop::Default)
    .elevation(Elevation::Admin)
    .run()?;
```

Start a process as Local System on the Secure desktop:

```rust,no_run
use win_run::{Desktop, Elevation, win};

win("/path/to/executable")
    .args("-flag")
    .directory("/parent/directory")
    .desktop(Desktop::Secure)
    .elevation(Elevation::LocalSystem)
    .run()?;
```

### License

Licensed under [MIT license](https://github.com/hristogochev/win_run/blob/main/LICENSE).
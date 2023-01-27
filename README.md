# win_run
Run any executable as User, Admin or Local System from a Windows Service.

### Usage

To use this crate, add `win_run` as a dependency to your project's `Cargo.toml`:

```toml
[dependencies]
win_run = "0.1.1"
```

### Important
In order for any of the functions offered by the library to work they must be executed from a Windows Service!

### Examples

Start a process as Admin on the Default desktop:

```rust,no_run
use win_run::{Desktop, Elevation, run};

run("/executable/path", "args", "/current/directory/", Desktop::Default, Elevation::Admin)?;
```

Start a process as Local System on the Secure desktop:

```rust,no_run
use win_run::{Desktop, Elevation, run};

run("/executable/path", "args", "/current/directory/", Desktop::Secure, Elevation::LocalSystem)?;
```

### License

Licensed under [MIT license](https://github.com/hristogochev/merkle_hash/blob/main/LICENSE).
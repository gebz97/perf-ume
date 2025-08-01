//use anyhow::Ok;
use anyhow::{Result, Context, anyhow};
use nix::unistd::{User, Uid};
use clap::{Parser, ArgGroup};

#[derive(Parser, Debug)]
#[command(author, version, about)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .args(&["user", "pid", "ptree"])
))]
struct Cli {
    /// Username or UID
    #[arg(short = 'u', long = "user", group = "target")]
    user: Option<String>,

    /// Single PID inspect
    #[arg(short = 'p', long = "pid", group = "target")]
    pid: Option<u32>,

    /// PID + full process tree
    #[arg(short = 'P', long = "ptree", group = "target")]
    ptree: Option<u32>,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    if let Some(user_str) = args.user {
        let uid = resolve_uid(&user_str)?;
        let pids = collect_pids_for_uid(uid)?;
        inspect_pid_list(&pids)?;
    } else if let Some(pid) = args.pid {
        inspect_single_pid(pid)?;
    } else if let Some(tree_pid) = args.ptree {
        inspect_pid_tree(tree_pid)?;
    } else {
        unreachable!("Clap guarantees exactly one target");
    }

    Ok(())
}

fn resolve_uid(user_str: &str) -> Result<u32> {
    // parse numeric UID or resolve username via nix::unistd::User
    if let Ok(uid) = user_str.parse::<u32>() {
        return Ok(uid);
    }
    let user = nix::unistd::User::from_name(user_str)
        .context(format!("Failed user lookup for '{}'", user_str))?
        .ok_or_else(|| anyhow!("User '{}' not found", user_str))?;
    Ok(user.uid.as_raw())
}

fn collect_pids_for_uid(uid: u32) -> Result<Vec<u32>> {
    // via procfs::process::all_processes(), filter by stat.uid
    unimplemented!()
}

fn inspect_single_pid(pid: u32) -> Result<()> {
    // Only inspect the specified PID
    unimplemented!()
}

fn inspect_pid_tree(root_pid: u32) -> Result<()> {
    // Build process tree under root_pid, then inspect each
    unimplemented!()
}

fn inspect_pid_list(pids: &[u32]) -> Result<()> {
    // Central logic to walk tree or list, collect limits + usage, compare, report
    unimplemented!()
}
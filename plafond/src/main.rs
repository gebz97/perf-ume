use std::{collections::{HashMap, HashSet}, fs, io::{BufRead, BufReader}, path::PathBuf, process};
use anyhow::{Result, Context, anyhow};
use nix::unistd::{User, Uid};
use clap::{ArgGroup, CommandFactory, Parser};

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

struct ProcStats {
    // Control data
    pid: u32,
    name: String,
    cmd: String,

    // Open file data
    open_fds: u64,
    fd_soft_limit: u64,
    fd_hard_limit: u64,

    // Mem data
    vm_rss: u64,
    vm_size: u64,
    vm_locked: u64,
    mem_soft_limit: Option<u64>,
    mem_hard_limit: Option<u64>,

    // Process stuff
    threads: u32,
    threads_soft_limit: Option<u64>,
    threads_hard_limit: Option<u64>,

    // RLimits
    rlimits: HashMap<String, (u64, u64)>
}

impl ProcStats {
    pub fn gather(pid: u32) -> Result<ProcStats> {
        let pid_path = PathBuf::from(format!("/proc/{pid}"));

        let name = match Self::read_name(&pid_path) {
            Ok(n) => n,
            Err(e) => return Err(anyhow!("Failed to read process name: {e}")),
        };

        let cmd = match Self::read_cmdline(&pid_path) {
            Ok(c) => c,
            Err(e) => return Err(anyhow!("Failed to read cmdline: {e}")),
        };

        let open_fds = match Self::count_open_fds(&pid_path) {
            Ok(n) => n,
            Err(_) => 0, // Default to 0 if inaccessible
        };

        let (
            rlimits, fd_limits, mem_limits, thread_limits
        ) = match Self::parse_limits(&pid_path) {
            Ok(v) => v,
            Err(e) => return Err(anyhow!("Failed to parse limits: {e}")),
        };

        let (
            vm_rss, vm_size, vm_locked, threads
        ) = match Self::parse_status(&pid_path) {
            Ok(v) => v,
            Err(e) => return Err(anyhow!("Failed to parse status: {e}")),
        };

        Ok(ProcStats {
            pid,
            name,
            cmd,
            open_fds,
            fd_soft_limit: fd_limits.0,
            fd_hard_limit: fd_limits.1,
            mem_soft_limit: Some(mem_limits.0),
            mem_hard_limit: Some(mem_limits.1),
            threads,
            threads_soft_limit: Some(thread_limits.0),
            threads_hard_limit: Some(thread_limits.1),
            vm_rss,
            vm_size,
            vm_locked,
            rlimits,
        })
    }

    pub fn read_name(pid_path: &PathBuf) -> Result<String> {
        match fs::read_to_string(pid_path.join("comm")) {
            Ok(s) => Ok(s.trim().to_string()),
            Err(e) => Err(anyhow!(e))
        }
    }

    pub fn read_cmdline(pid_path: &PathBuf) -> Result<String> {
        Ok(todo!())
    }

    pub fn count_open_fds(pid_path: &PathBuf) -> Result<u64> {
        match fs::read_dir(pid_path.join("fd")) {
            Ok(dir) => Ok(dir.count() as u64),
            Err(e) => Err(anyhow!(e))
        }
    }

    pub fn parse_limits(
        pid_path: &PathBuf
    ) -> Result<(
        HashMap<String, (u64, u64)>,
        (u64, u64),
        (u64, u64),
        (u64, u64),
    )> {
        let mut rlimits = HashMap::new();
        let mut fd_limits = (0,0);
        let mut mem_limits = (0,0);
        let mut thread_limits = (0,0);

        let file = match fs::File::open(pid_path.join("limits")) {
            Ok(f) => f,
            Err(e) => return Err(anyhow!(e))
        };

        let reader = BufReader::new(file);

        for line in reader.lines().skip(1) {
            if let Ok(l) = line {
                let parts: Vec<_> = l.split_whitespace().collect();
                if parts.len() >= 4 {
                    let name = parts[..parts.len() - 3].join(" ");
                    let soft = parse_limit(parts[parts.len() - 3]);
                    let hard = parse_limit(parts[parts.len() - 2]);

                    match name.as_str() {
                        "Max open files" => fd_limits = (soft, hard),
                        "Max address space" => mem_limits = (soft, hard),
                        "Max processes" => thread_limits = (soft, hard),
                        _ => {}
                    }

                    rlimits.insert(name, (soft, hard));
                }
            }
        }


        Ok((rlimits, fd_limits, mem_limits, thread_limits))
    }

    pub fn parse_status(pid_path: &PathBuf) -> Result<(u64, u64, u64, u32)> {
        let file = match fs::File::open(pid_path.join("status")) {
            Ok(f) => f,
            Err(e) => return Err(anyhow!(e)),
        };
    
        let mut vm_rss = 0;
        let mut vm_size = 0;
        let mut vm_locked = 0;
        let mut threads = 0;
    
        for line in BufReader::new(file).lines() {
            if let Ok(l) = line {
                if l.starts_with("VmRSS:") {
                    vm_rss = extract_kb(&l);
                } else if l.starts_with("VmSize:") {
                    vm_size = extract_kb(&l);
                } else if l.starts_with("VmLck:") {
                    vm_locked = extract_kb(&l);
                } else if l.starts_with("Threads:") {
                    threads = l.split_whitespace()
                        .nth(1)
                        .unwrap_or("0")
                        .parse()
                        .unwrap_or(0);
                }
            }
        }
    
        Ok((vm_rss, vm_size, vm_locked, threads))
    }
}

fn main() -> Result<()> {
    let args = Cli::parse();

    if let Err(e) = handle_cli_args(args) {
        eprintln!("Error: {e}");
        process::exit(1);
    }

    if let Err(e) = print_sys_stats() {
        eprintln!("Error: {e}");
        process::exit(1);
    }

    Ok(())
}

fn handle_cli_args(args: Cli) -> Result<()> {
    match (args.user, args.pid, args.ptree) {
        (Some(user_str), None, None) => handle_user_arg(user_str),
        (None, Some(pid), None) => handle_pid_arg(pid),
        (None, None, Some(tree_pid)) => handle_ptree_arg(tree_pid),
        _ => {
            let _ = Cli::command().print_help();
            println!();
            process::exit(1);
        }
    }
}

fn handle_user_arg(user_str: String) -> Result<()> {
    let uid = match resolve_uid(&user_str) {
        Ok(uid) => uid,
        Err(e) => return Err(e),
    };

    let pids = match collect_pids_for_uid(uid) {
        Ok(pids) => pids,
        Err(e) => return Err(e),
    };

    if let Err(e) = inspect_pid_list(&pids) {
        eprintln!("Failed to inspect PIDs for user {uid}, Error: {e}")
    }
    Ok(())
}

fn handle_pid_arg(pid: u32) -> Result<()> {
    match inspect_single_pid(pid) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

fn handle_ptree_arg(ppid: u32) -> Result<()> {
    if let Err(e) = contruct_ptree_for_ppid(ppid) {
        eprintln!("Failed to inspect PIDs for user {ppid}, Error: {e}")
    }
    match inspect_pid_tree(ppid) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

fn resolve_uid(user_str: &str) -> Result<u32> {
    if let Ok(uid) = user_str.parse::<u32>() {
        return Ok(uid);
    }

    let result = nix::unistd::User::from_name(user_str)
        .with_context(|| format!("Failed user lookup for '{}'", user_str));

    let user_opt = match result {
        Ok(opt) => opt,
        Err(e) => return Err(e),
    };

    let user = match user_opt {
        Some(user) => user,
        None => return Err(anyhow!("User '{}' not found", user_str)),
    };

    Ok(user.uid.as_raw())
}

// Placeholder implementations
fn collect_pids_for_uid(uid: u32) -> Result<Vec<u32>> {
    // Example: scan /proc/*/status, filter by Uid
    unimplemented!()
}

fn inspect_single_pid(pid: u32) -> Result<()> {
    // Check limits/usage for one PID
    unimplemented!()
}

fn contruct_ptree_for_ppid(ppid: u32) -> Result<Vec<ProcStats>> {
    unimplemented!()
}

fn inspect_pid_tree(root_pid: u32) -> Result<()> {
    // Recursively traverse children
    unimplemented!()
}

fn inspect_pid_list(pids: &[u32]) -> Result<()> {
    // Loop through list, analyze usage vs. limits
    unimplemented!()
}

fn print_sys_stats() -> Result<()> {
    // Optional global info: mem, load, swap, etc.
    unimplemented!()
}

fn parse_limit(s: &str) -> u64 {
    if s == "unlimited" {
        u64::MAX
    } else {
        s.parse().unwrap_or(0)
    }
}

fn extract_kb(line: &str) -> u64 {
    match line.split_whitespace().nth(1) {
        Some(val) => match val.parse::<u64>() {
            Ok(n) => n * 1024,
            Err(_) => 0,
        },
        None => 0,
    }
}
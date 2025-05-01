use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::ptrace;
use nix::unistd::{fork, getpid, ForkResult, Pid};
use std::collections::HashMap;
use std::io::{self, Write, BufRead};
use std::process::{exit, Command as StdCommand};
use std::fs::write;
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};
use chrono::{Local, DateTime};
use tokio::{self, sync::RwLock,time::{timeout, Duration},
    fs::File as TokioFile,
    io::{BufReader as AsyncBufReader, AsyncBufReadExt},
    process::Command as TokioCommand,
};
use tracing::{info, error, Level};
use tracing_subscriber;
// Function to get PID from user input
fn get_pid_from_user() -> i32 {
    print!("Please enter the corresponding PID to inspect: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().parse().unwrap_or_else(|_| {
        eprintln!("Invalid PID, exiting the program...");
        exit(1);
    })
}
// Function to get system uptime in seconds from the /proc/uptime file inside the linux kernel
fn get_system_uptime() -> f64 {
    let content = std::fs::read_to_string("/proc/uptime").unwrap();
    content
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<f64>()
        .unwrap()
}
// Function to convert process start time (ticks) to a readable timestamp
fn convert_start_time_to_timestamp(start_ticks: u64) -> String {
    let uptime_secs = get_system_uptime();
    // Convert ticks to seconds (assuming CLOCKS_PER_SEC = 100 on most systems)
    let start_secs = start_ticks as f64 / 100.0;
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as f64;
    let boot_time = current_time - uptime_secs;
    let process_start_time = boot_time + start_secs;
    // Convert to a readable timestamp
    let start_datetime = DateTime::<Local>::from(UNIX_EPOCH + StdDuration::from_secs(process_start_time as u64));
    start_datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}
// Function to search logs for activity related to the PID
async fn search_logs(pid: i32) -> String {
    let script = format!(
        "#!/bin/bash\njournalctl _PID={} -n 5 --no-pager --output=short-precise 2>/dev/null",
        pid
    );
    tokio::fs::write("/tmp/search_logs.sh", script).await.expect("Failed to write script");
    let output = TokioCommand::new("sh")
        .arg("/tmp/search_logs.sh")
        .output()
        .await
        .expect("Failed to execute log search script");
    String::from_utf8_lossy(&output.stdout).to_string()
}
// Function to gather process information 
async fn gather_process_info(pid: i32) -> (String, String, String, Vec<i32>, String) {
    let status_file = format!("/proc/{}/status", pid);
    let mut user = String::new();
    let mut ppid = String::new();
    let mut start_time = String::new();
    if let Ok(file) = std::fs::File::open(&status_file) {
        let reader = std::io::BufReader::new(file);
        for line in reader.lines().flatten() {
            if line.starts_with("Uid:") {
                let uid: i32 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
                user = StdCommand::new("id")
                    .arg("-un")
                    .arg(uid.to_string())
                    .output()
                    .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                    .unwrap_or("Unknown".to_string());
            } else if line.starts_with("PPid:") {
                ppid = line.split_whitespace().nth(1).unwrap().to_string();
            } else if line.starts_with("Start:") {
                let ticks: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
                start_time = convert_start_time_to_timestamp(ticks);
            }
        }
    }
    // Find children using ps
    let children_output = StdCommand::new("ps")
        .arg("--ppid")
        .arg(pid.to_string())
        .arg("-o")
        .arg("pid")
        .arg("--no-headers")
        .output()
        .expect("Failed to execute ps");
    let children: Vec<i32> = String::from_utf8_lossy(&children_output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect();
    let log_info = search_logs(pid).await;
    (user, ppid, start_time, children, log_info)
}
// Function to display process information
fn display_process_info(pid: i32, user: &str, ppid: &str, start_time: &str, children: &[i32], log_info: &str) -> String {
    let report = format!(
        "\n=== Process Monitoring Report ===\n
PID: {}\n
User: {}\n
Parent PID: {}\n
Start Time: {}\n
Current Time: {}\n
Children PIDs: {:?}\n
\nLog Entries (last 5 related lines):\n{}\n
==============================\n",
        pid,
        user,
        ppid,
        start_time,
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        children,
        if log_info.is_empty() { "No related log entries found." } else { log_info }
    );
    println!("{}", report);
    report
}
// Function to save the report to a file in the /tmp directory with the current timestamp and the PID
fn save_report_to_file(report: &str, pid: i32) {
    let filename = format!("/tmp/pid_report_{}_{}.txt", pid, Local::now().format("%Y%m%d_%H%M%S"));
    write(&filename, report).expect("Failed to save report to file");
    println!("Report saved to {}", filename);
}
// Initialize logging system
fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();
}
// Use structured logging throughout the code
fn monitor_with_ptrace(pid: i32) -> anyhow::Result<()> {
    info!(target_pid = pid, "Starting process monitoring");
    match ptrace::attach(Pid::from_raw(pid)) {
        Ok(_) => info!("Successfully attached to process"),
        Err(e) => {
            error!(error = ?e, "Failed to attach to process");
            return Err(e.into());
        }
    }
    loop {
        match waitpid(Pid::from_raw(pid), None)? {
            WaitStatus::PtraceSyscall(pid) => {
                println!("PID {} made a system call", pid);
            }
            WaitStatus::Exited(pid, code) => {
                println!("PID {} exited with status {}", pid, code);
                break;
            }
            status => {
                println!("Unexpected status: {:?}", status);
                break;
            }
        }
        ptrace::syscall(Pid::from_raw(pid), None)?;
    }
    ptrace::detach(Pid::from_raw(pid), None)?;
    Ok(())
}

#[tokio::main]
async fn main() {
    setup_logging();
    println!("Process Inspection Operation started...");
    let pid = get_pid_from_user();
    let (user, ppid, start_time, children, log_info) = gather_process_info(pid).await;
    let report = display_process_info(pid, &user, &ppid, &start_time, &children, &log_info);
    save_report_to_file(&report, pid);
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            println!("Monitoring child with PID: {}", child);
            loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        println!("Monitoring child exited with status {}", code);
                        break;
                    }
                    Ok(status) => println!("Monitoring child status: {:?}", status),
                    Err(err) => {
                        eprintln!("Waitpid failed: {}", err);
                        break;
                    }
                }
            }
        }
        Ok(ForkResult::Child) => {
            println!("Child (PID: {}) starting real-time monitoring for PID {}...", getpid(), pid);
            monitor_with_ptrace(pid).unwrap();
            println!("Child (PID: {}) finished monitoring.", getpid());
            exit(0);
        }
        Err(err) => {
            eprintln!("Fork failed: {}", err);
            exit(1);
        }
    }
}

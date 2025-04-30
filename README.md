# PrIDamoN
Process inspector and monitoring toolset for Linux OS
# PID Monitor Advanced - Function Documentation
This document describes each function in the `PrIDamoN` application and explains its role in the overall workflow. The tool is designed for real-time inspection and monitoring of Linux processes.

---

## Function Reference

### `get_pid_from_user()`
**Purpose:** Prompt the user to input a PID.

**Description:**
- Prints a prompt to standard output.
- Reads input from `stdin`.
- Parses the input as an integer.
- If parsing fails, prints an error and exits.

---

### `get_system_uptime()`
**Purpose:** Retrieve the system uptime in seconds.

**Description:**
- Reads the content of `/proc/uptime`.
- Parses the first number (total uptime) as a `f64`.
- Returns the uptime in seconds.

---

### `convert_start_time_to_timestamp(start_ticks: u64)`
**Purpose:** Convert a process's start time in clock ticks to a human-readable timestamp.

**Description:**
- Calculates the system boot time using uptime.
- Adds the process's start time (in seconds) to the boot time.
- Returns a formatted date/time string (local time).

---

### `search_logs(pid: i32)` (async)
**Purpose:** Fetch the last 5 journal entries related to the PID.

**Description:**
- Constructs a small bash script using `journalctl`.
- Writes the script to `/tmp/search_logs.sh`.
- Executes the script asynchronously.
- Returns the output as a `String`.

---

### `gather_process_info(pid: i32)` (async)
**Purpose:** Collect all available information about a process.

**Description:**
- Reads `/proc/[pid]/status` to extract UID, PPID, and start time.
- Resolves UID to a username using the `id` command.
- Uses the `ps` command to find child PIDs.
- Calls `search_logs()` to collect journal entries.
- Returns a tuple of user, parent PID, start time, child PIDs, and log information.

---

### `display_process_info(...)`
**Purpose:** Format and display all collected process information.

**Description:**
- Formats a multi-line report with all collected data.
- Prints the report to stdout.
- Returns the formatted string.

---

### `save_report_to_file(report: &str, pid: i32)`
**Purpose:** Save the report to a timestamped file in `/tmp`.

**Description:**
- Constructs a filename using the PID and current time.
- Writes the report string to the file.
- Prints the path to the saved report.

---

### `setup_logging()`
**Purpose:** Initialize the `tracing` logging subsystem.

**Description:**
- Sets logging level to INFO.
- Enables logging with thread ID, file, and line number context.

---

### `monitor_with_ptrace(pid: i32)`
**Purpose:** Attach to and monitor system calls from a given PID.

**Description:**
- Uses `ptrace` to attach to the target process.
- Monitors for syscall events in a loop.
- Handles process exit and unexpected states.
- Detaches when done.

---

### `main()` (async)
**Purpose:** Main entry point of the application.

**Description:**
- Initializes logging.
- Prompts for PID.
- Gathers and displays process info.
- Saves the report.
- Forks a child process to attach `ptrace` for syscall monitoring.

---

## Additional Notes
- Async functions (`search_logs`, `gather_process_info`) use `tokio`.
- Logging uses `tracing` and `tracing_subscriber`.
- Process info is mostly gathered from `/proc`, `ps`, and `journalctl`.
- System call monitoring is done via `nix` and `ptrace`.

This documentation helps future contributors or maintainers understand each component's role in the monitoring pipeline.


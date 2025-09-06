# Bash Job Control Summary with Definitions

## Key Definitions

**Job Control** - Bash's system for managing multiple processes, allowing you to start, stop, pause, and switch between them.

**Foreground Process** - A process that runs actively in the terminal, blocking shell access until it completes. Only one can run at a time per terminal.

**Background Process** - A process that runs without blocking the terminal, allowing you to continue using the shell. Multiple background processes can run simultaneously.

**Job** - A process or group of processes managed by the shell's job control system, referenced by job numbers (like %1, %2).

**Signal** - A message sent by the kernel to processes to request state changes or termination.

**PID (Process ID)** - A unique numerical identifier assigned to each running process by the system.

## Key Process Control Commands

**Basic Control:**
- `CTRL + C` - Send SIGINT signal to terminate a running foreground process
- `CTRL + Z` - Send SIGTSTP signal to suspend a foreground process (pause it)
- `command &` - Start a process in the background
- `jobs` - List all background/stopped processes with their job numbers

**Moving Between States:**
- `fg` - Move most recent background process to foreground
- `bg` - Resume most recent stopped process in background  
- `fg %1` or `bg %1` - Work with specific job numbers

## Most Practical Techniques

**For Long-Running Tasks:**
- Add `&` at the end to run in background: `ping google.com &`
- Use `CTRL + Z` then `bg` if you forgot to add `&` initially

**Keeping Processes Alive After Terminal Closes:**
- `nohup command &` - Process survives terminal closure (immune to SIGHUP), output saved to `nohup.out`
- `disown %1` - Remove job from terminal's job control completely
- `disown -h %1` - Mark job to ignore SIGHUP signals but keep job control active

**Process Management:**
- `kill %1` - Kill background job by job number
- `pgrep -a processname` - Find process ID of running processes  
- `kill PID` - Kill process by its process ID

## Important Signals

**SIGINT** - Interrupt signal sent by `CTRL + C`, requests process termination
**SIGTSTP** - Terminal stop signal sent by `CTRL + Z`, suspends process execution
**SIGHUP** - Hangup signal sent when terminal closes, typically terminates associated processes

## Key Insight
Job control provides flexibility to start processes, move them between foreground/background as needed, and keep important tasks running even when closing terminals, all without opening multiple terminal windows. This is essential for efficient command-line workflow management.
# Bash Scripting Tutorial Summary with Definitions

## Key Definitions

**Bash Script** - A file containing a sequence of commands executed by the bash program line by line, allowing automation of repetitive tasks.

**Shell** - A program that provides a command-line interface for interacting with an operating system. Bash is a specific type of shell.

**Shebang** - The first line of a script (`#!/bin/bash`) that tells the system which interpreter to use to execute the script.

**Variable** - A storage location with a name that holds data (strings, numbers, etc.). In Bash, all variables are treated as strings by default.

**Command Substitution** - Using backticks `` `command` `` or `$(command)` to capture the output of a command and use it as a value.

**Exit Code** - A numerical value returned by a command indicating success (0) or failure (non-zero).

**Cron** - A time-based job scheduler in Unix-like systems for automating script execution.

## Essential Script Structure

**Basic Script Template:**
```bash
#!/bin/bash
# Comments start with #
echo "Hello World"
```

**Making Scripts Executable:**
- `chmod u+x script.sh` - Give execute permission
- Run with: `./script.sh`, `bash script.sh`, or `sh script.sh`

## Core Scripting Concepts

**Variables:**
- Assignment: `name="value"` (no spaces around =)
- Access: `echo $name` or `echo ${name}`
- Command substitution: `current_date=$(date)`

**Input/Output:**
- `read variable_name` - Get user input
- `echo "text"` - Display output
- `echo "text" > file.txt` - Write to file (overwrite)
- `echo "text" >> file.txt` - Append to file

**Command Line Arguments:**
- `$1`, `$2`, `$3` - First, second, third arguments
- `$0` - Script name itself

## Control Structures

**Conditional Statements:**
```bash
if [ condition ]; then
    # commands
elif [ condition ]; then
    # commands
else
    # commands
fi
```

**Loops:**
```bash
# While loop
while [ condition ]; do
    # commands
done

# For loop
for i in {1..5}; do
    echo $i
done
```

**Case Statements:**
```bash
case $variable in
    pattern1)
        # commands
        ;;
    pattern2)
        # commands
        ;;
    *)
        # default case
        ;;
esac
```

## Common Comparison Operators

- `-eq` - Equal to
- `-ne` - Not equal to
- `-gt` - Greater than
- `-lt` - Less than
- `-ge` - Greater than or equal
- `-le` - Less than or equal

## Essential Commands

**File Operations:**
- `ls` - List directory contents
- `cd` - Change directory
- `mkdir` - Create directory
- `touch` - Create file
- `rm` - Remove files/directories
- `cp` - Copy files
- `mv` - Move/rename files

**Text Processing:**
- `echo` - Print text
- `cat` - Display file contents
- `grep` - Search text patterns

## Automation with Cron

**Cron Syntax:** `minute hour day month weekday command`
- `0 0 * * *` - Daily at midnight
- `*/5 * * * *` - Every 5 minutes
- `0 6 * * 1-5` - 6 AM Monday-Friday

**Cron Management:**
- `crontab -l` - List scheduled jobs
- `crontab -e` - Edit cron jobs

## Debugging Techniques

**Debug Options:**
- `set -x` - Show each command as it executes
- `set -e` - Exit on first error
- `echo $?` - Check exit code of last command

**Troubleshooting:**
- Add `echo` statements to track variable values
- Check cron logs at `/var/log/syslog` (Ubuntu/Debian)
- Use `which bash` to verify bash path for shebang

## Key Advantages

**Why Use Bash Scripting:**
- **Automation** - Eliminate repetitive manual tasks
- **Portability** - Works across Unix/Linux systems
- **Integration** - Easily combines with other tools and commands
- **Accessibility** - No special software required, just a text editor
- **Debugging** - Built-in error reporting and debugging tools

## Best Practices

- Use descriptive variable names
- Add comments to explain complex logic
- Always include shebang line
- Use quotes around variables: `"$variable"`
- Check exit codes for error handling
- Test scripts thoroughly before automation
find /path/to/dir -name "*.log" -exec rm {} > /dev/null \; && grep "error" /path/to/logs > /dev/null 2>&1 && ps aux | grep "my_process" > /dev/null

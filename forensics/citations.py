"""Settings for checking the AI's citations.

When the AI writes "explorer.exe (PID 2000) [R12:3]", the app checks that the values next to the
citation (explorer.exe, 2000) really appear in row R12:3. If not, the citation is marked
"unsupported" in the answer. These settings decide which values are checked.

TODO(forensics): review against real output and real AI answers.
"""

# Words ending in one of these extensions are checked as file names (evil.ps1, lsass.exe).
FILE_EXTENSIONS = [
    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js", "cpl", "ocx", "com", "msi",
    "lnk", "dmp", "bin", "dat", "tmp", "log", "txt", "zip", "db",
]  # fmt: skip

# A number is only checked when one of these words comes right before it ("PID 1234",
# "port: 443"). Bare numbers ("3 processes") are never checked: they are usually counts.
NUMBER_LABELS = [
    "PPID", "PID", "TID", "port", "parent process id", "parent id", "process id", "thread id",
]  # fmt: skip

# Windows cuts process names in pslist to this many characters, so "svchost_updater.exe" in the
# answer may match "svchost_update" in the row.
TRUNCATED_NAME_LENGTH = 14

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__version__ = "1.0.0"
__description__ = """
This script lists processes that have packet sockets open by parsing /proc/net/packet.

It accesses /proc/net/packet and /proc/[pid]/fd directly to find processes associated with 
packet sockets. It can help find processes that are sniffing network traffic without relying
on external tools like lsof.

Sandfly Security - www.sandflysecurity.com
Agentless Endpoint Detection and Response (EDR) for Linux
"""
__license__ = "Licensed under the MIT License (MIT)"

import os
import sys


def error(msg: str) -> None:
    # Print the error message to stderr and exit with a status of 1.
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(1)


def check_root_privilege() -> None:
    # Ensure the script is run with root privileges.
    if os.geteuid() != 0:
        error("This script must be run as root. Please use 'sudo' or switch to the root user.")


def show_inodes_from_packet_file() -> set:
    # Read /proc/net/packet, skip header, and extract unique inode numbers.
    packet_file = "/proc/net/packet"
    if not os.path.exists(packet_file):
        error(f"{packet_file} not found.")
    inodes = set()
    try:
        with open(packet_file, "r") as f:
            next(f)  # Skip the header line
            inodes = {line.strip().split()[-1] for line in f}
    except Exception as e:
        error(str(e))
    if not inodes:
        print(f"No inodes found in {packet_file}. No packet sockets are currently open.")
        sys.exit(0)
    print(f"Found the following unique inodes in {packet_file}:")
    print("\n".join(sorted(inodes)))
    print()
    return inodes


def get_process_name(pid_dir: str) -> str:
    # Get the process name from the /proc/[pid]/[comm|exe] files.
    comm_file = os.path.join(pid_dir, "comm")
    exe_file = os.path.join(pid_dir, "exe")
    try:
        if os.path.isfile(comm_file):
            with open(comm_file, "r") as f:
                return f.read().strip()
        elif os.path.islink(exe_file):
            return os.path.basename(os.readlink(exe_file))
    except OSError:
        pass
    return "Unknown"


def show_processes_using_inodes(inodes: set) -> None:
    # Display processes using the specified inodes.
    proc_dir = "/proc"
    for packet_inode in inodes:
        print(f"Searching for processes with packet socket inode: {packet_inode}")
        found_process = False
        for pid in os.listdir(proc_dir):
            if not pid.isdigit():
                continue
            pid_dir = os.path.join(proc_dir, pid)
            fd_dir = os.path.join(pid_dir, "fd")
            if not os.path.isdir(fd_dir):
                continue
            try:
                for fd in os.listdir(fd_dir):
                    fd_path = os.path.join(fd_dir, fd)
                    target = os.readlink(fd_path)
                    if f"socket:[{packet_inode}]" == target:
                        process_name = get_process_name(pid_dir)
                        print(f"  PID: {pid} (Name: {process_name})")
                        print(f"    FD: {fd} -> {target}")
                        found_process = True
            except OSError:
                continue
        if not found_process:
            print(f"No process found with a file descriptor linking to inode {packet_inode}.")
            print("This may indicate that a process is grabbing packets but is not showing itself in /proc.")
            print(
                "If you suspect a hidden process, consider using tools like 'sandfly-process-decloak' for further investigation.")
        print("-" * 69)


if __name__ == "__main__":
    print("Parsing inodes from /proc/net/packet and finding associated processes")
    print("-" * 69)
    check_root_privilege()
    inodes = show_inodes_from_packet_file()
    show_processes_using_inodes(inodes)
    print("Script finished.")

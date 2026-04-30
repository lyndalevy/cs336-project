# test_cmdinject.py — OS command injection: user input passed to os.system
import os

def ping_host():
    host = input("Enter hostname to ping: ")   # SOURCE
    os.system(f"ping -c 1 {host}")             # SINK — command injection!

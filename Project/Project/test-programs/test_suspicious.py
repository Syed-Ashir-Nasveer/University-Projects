
import os
import sys
import subprocess

print("⚠ WARNING: This program demonstrates suspicious behavior")
print("Running in sandbox for analysis...\n")

print("1. Attempting to access system directories...")
try:
    system_dir = "C:\\Windows\\System32" if os.name == 'nt' else "/etc"
    files = os.listdir(system_dir)
    print(f"✗ Accessed {len(files)} system files")
except Exception as e:
    print(f"✓ Blocked: {e}")

print("\n2. Attempting to spawn child process...")
try:
    subprocess.Popen([sys.executable, "-c", "print('Child process')"])
    print("✗ Child process created")
except Exception as e:
    print(f"✓ Blocked: {e}")

print("\n3. Attempting to modify environment...")
try:
    os.environ['MALICIOUS_VAR'] = 'value'
    print("✗ Environment modified")
except Exception as e:
    print(f"✓ Blocked: {e}")

print("\n4. High CPU usage simulation...")
for i in range(5):
    sum_val = sum(range(10000000))
    print(f"   Iteration {i+1}: CPU spike")

print("\nSuspicious behavior analysis complete")

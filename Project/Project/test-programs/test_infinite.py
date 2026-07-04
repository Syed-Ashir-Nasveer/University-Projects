import time

print("Starting infinite loop (test termination feature)...")
print("Press Stop button to terminate")

counter = 0
while True:
    counter += 1
    if counter % 10 == 0:
        print(f"Loop iteration: {counter}")
    time.sleep(0.1)


# =============================================================================
# Test Program 7: Multi-threaded
# Save as: test_multithreaded.py

import threading
import time

def worker(thread_id):
    print(f"Thread {thread_id} started")
    for i in range(5):
        print(f"Thread {thread_id}: iteration {i}")
        time.sleep(0.5)
    print(f"Thread {thread_id} finished")

print("Starting multi-threaded test...")

threads = []
for i in range(4):
    t = threading.Thread(target=worker, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print("All threads completed")

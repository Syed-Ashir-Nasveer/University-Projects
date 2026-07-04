import time

print("Starting resource test...")

data = []
for i in range(10):
    print(f"Iteration {i+1}: Allocating memory...")
    data.append([0] * 1000000)  # Allocate memory
    
    # CPU intensive task
    sum_val = 0
    for j in range(1000000):
        sum_val += j
    
    time.sleep(0.5)

print("Resource test completed")
import sys

print("Memory allocation test...")

class DataHolder:
    def __init__(self, size):
        self.data = [0] * size
    
    def __del__(self):
        print(f"Releasing {len(self.data)} items")

objects = []
for i in range(5):
    size = 1000000 * (i + 1)
    print(f"Allocating {size} items...")
    obj = DataHolder(size)
    objects.append(obj)
    
    print(f"Current memory: {sys.getsizeof(objects)} bytes")

print("Releasing all objects...")
objects.clear()

print("Memory test complete")
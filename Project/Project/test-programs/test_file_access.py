import os

print("Testing file operations...")

try:
    with open('sandbox_test.txt', 'w') as f:
        f.write("Test data from sandbox")
    print("✓ File write successful")
    
    with open('sandbox_test.txt', 'r') as f:
        content = f.read()
    print(f"✓ File read successful: {content}")
    
    os.remove('sandbox_test.txt')
    print("✓ File delete successful")
    
except Exception as e:
    print(f"✗ File operation failed: {e}")

try:
    restricted_path = os.path.expanduser("~/important_file.txt")
    with open(restricted_path, 'w') as f:
        f.write("Attempting restricted access")
    print("⚠ Restricted access succeeded (should be blocked)")
except Exception as e:
    print(f"✓ Restricted access blocked: {e}")

print("File access test completed")
#!/usr/bin/env python3
import os
import sys
from concurrent.futures import ThreadPoolExecutor
import random

def generate_function_file(i, base_dir):
    """Generate a single .cpp file with a function"""
    func_name = f"test_function_{i}"
    cpp_content = f"""#include <iostream>
#include <vector>
#include <string>
#include <cmath>

// Function {i}
int {func_name}() {{
    int result = {i};
    
    // Some computation to make it realistic
    for (int j = 0; j < {random.randint(10, 100)}; ++j) {{
        result += j * {random.randint(1, 10)};
    }}
    
    std::vector<int> data({random.randint(50, 200)});
    for (size_t k = 0; k < data.size(); ++k) {{
        data[k] = k * {random.randint(1, 5)};
    }}
    
    return result % 1000;
}}
"""

    # Write .cpp file
    with open(f"{base_dir}/file{i}.cpp", 'w') as f:
        f.write(cpp_content)

    # Write .h file
    header_content = f"""#pragma once
extern int test_function_{i}();
"""
    with open(f"{base_dir}/include/file{i}.h", 'w') as f:
        f.write(header_content)

def generate_main_file(base_dir, num_files):
    """Generate main.cpp that calls all functions"""
    main_content = """#include <iostream>
#include <chrono>

"""

    # Add includes (in chunks to avoid massive compile times)
    chunk_size = min(1000, num_files)
    for i in range(0, min(chunk_size, num_files)):
        main_content += f'#include "include/file{i}.h"\n'

    main_content += f"""
int main() {{
    std::cout << "Testing {num_files} functions...\\n";
    auto start = std::chrono::high_resolution_clock::now();
    
    int total = 0;
"""

    # Call functions (only first 1000 to keep compile time reasonable)
    for i in range(0, min(1000, num_files)):
        main_content += f"    total += test_function_{i}();\n"

    main_content += f"""
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Total result: " << total << "\\n";
    std::cout << "Time taken: " << duration.count() << "ms\\n";
    std::cout << "All tests completed!\\n";
    return 0;
}}
"""

    with open(f"{base_dir}/main.cpp", 'w') as f:
        f.write(main_content)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 generate_test_files.py <output_dir> <num_files>")
        sys.exit(1)

    base_dir = sys.argv[1]
    num_files = int(sys.argv[2])

    print(f"Generating {num_files} test files in {base_dir}...")

    # Create directories
    os.makedirs(base_dir, exist_ok=True)
    os.makedirs(f"{base_dir}/include", exist_ok=True)

    # Generate files in parallel
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = []

        for i in range(num_files):
            future = executor.submit(generate_function_file, i, base_dir)
            futures.append(future)

            if (i + 1) % 5000 == 0:
                print(f"Queued {i + 1} files...")

        # Wait for completion
        for i, future in enumerate(futures):
            future.result()
            if (i + 1) % 5000 == 0:
                print(f"Generated {i + 1}/{num_files} files...")

    # Generate main.cpp
    generate_main_file(base_dir, num_files)

    print(f"✅ Generated {num_files} files + main.cpp in {base_dir}")
    print(f"📊 Total files: {num_files * 2 + 1} (.cpp + .h + main.cpp)")

if __name__ == "__main__":
    main()

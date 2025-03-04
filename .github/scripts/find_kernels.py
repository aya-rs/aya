#!/usr/bin/env python3

import os
import glob
import sys
from typing import List

def find_kernels(directory: str) -> List[str]:
    return glob.glob(f"{directory}/**/vmlinuz-*", recursive=True)

def find_modules_directory(directory: str, kernel: str) -> str:
    matches = glob.glob(f"{directory}/**/modules/{kernel}", recursive=True)
    if len(matches) == 0:
        print(f"ERROR! No modules directory found for kernel {kernel}")
        sys.exit(1)
    return matches[0]

def main() -> None:
    images = find_kernels('test/.tmp')
    modules = []

    for image in images:
        image_name = os.path.basename(image).replace('vmlinuz-', '')
        module_dir = find_modules_directory('test/.tmp', image_name)
        modules.append(module_dir)
        
    if len(images) != len(modules):
        print(f"IMAGES={images}")
        print(f"MODULES={modules}")
        print("ERROR! len images != len modules")
        sys.exit(1)

    args = ' '.join(f"-i {image} -m {module}" for image, module in zip(images, modules))
    print(args)

if __name__ == "__main__":
    main()

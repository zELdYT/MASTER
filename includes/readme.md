## Directory Structure

The `includes` directory contains the following subdirectories:

- **`headers`**: Independent header files that can be used with DLLs or linked directly to your project.  
  These files also temporarily contain enumerations (enums) for various modules. This approach is not ideal but serves as a placeholder for the initial stages of the project.
- **`implementations`**: Contains implementation files for various functionalities, categorized by module (e.g., cryptography, math, etc.).

These directories are designed to keep the project modular and organized, allowing for easy integration and extension.

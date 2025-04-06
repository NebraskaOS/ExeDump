#include <iostream>
#include <fstream>
#include <string>
#include "mz.hpp"

struct DOSHeader {
    unsigned char signature[2]; // Expected to be 'MZ'
};

struct PEHeader {
    unsigned char signature[4]; // Expected to be 'PE\0\0'
};

bool isMZExecutable(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << path << "\n";
        return false;
    }

    char sig[2];
    file.read(sig, sizeof(sig));

    // Check for 'MZ' magic number
    return (sig[0] == 'M' && sig[1] == 'Z');
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <executable_file>\n";
        return 1;
    }

    std::string filepath = argv[1];

    if (!isMZExecutable(filepath)) {
        std::cout << "This file does not appear to be a valid MZ executable.\n";
        return 1;
    }

    analyzeMZExecutable(filepath);
    return 0;
}

// TODO: Add PE header analysis
// TODO: Add support for more files
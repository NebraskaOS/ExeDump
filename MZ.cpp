#include "MZ.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>

// Analyze an MZ (DOS) executable file
void analyzeMZExecutable(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filepath << "\n";
        return;
    }

    MZHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(MZHeader));

    std::cout << "\n=== MZ EXECUTABLE ANALYSIS ===\n\n";

    // Print out the header data
    std::cout << "Header Info:\n";
    std::cout << "------------\n";
    std::cout << "Signature: 0x" << std::hex << header.signature << "\n";
    std::cout << "Bytes on last page: " << std::dec << header.lastsize << "\n";
    std::cout << "Total pages: " << header.nblocks << "\n";
    std::cout << "Relocations: " << header.nreloc << "\n";
    std::cout << "Header size (paragraphs): " << header.hdrsize << "\n";
    std::cout << "Min alloc: " << header.minalloc << " paragraphs\n";
    std::cout << "Max alloc: " << header.maxalloc << " paragraphs\n";
    std::cout << "Initial SS: 0x" << std::hex << header.ss << "\n";
    std::cout << "Initial SP: 0x" << header.sp << "\n";
    std::cout << "Checksum: " << header.checksum << "\n";
    std::cout << "Initial IP: " << header.ip << "\n";
    std::cout << "Initial CS: " << header.cs << "\n";
    std::cout << "Relocation table offset: " << header.relocpos << "\n";
    std::cout << "Overlay number: " << std::dec << header.noverlay << "\n\n";

    // Estimate actual file size
    uint32_t fileSize = (header.nblocks - 1) * 512 + header.lastsize;
    std::cout << "Estimated file size: " << fileSize << " bytes\n\n";

    // Display relocation table if present
    if (header.nreloc > 0) {
        std::cout << "Relocation Table:\n";
        std::cout << "------------------\n";
        file.seekg(header.relocpos, std::ios::beg);

        for (int i = 0; i < header.nreloc; ++i) {
            RelocationEntry entry;
            file.read(reinterpret_cast<char*>(&entry), sizeof(RelocationEntry));
            std::cout << "Entry #" << i << " => Offset: 0x" << std::hex << entry.offset 
                      << ", Segment: 0x" << entry.segment << "\n";
        }
        std::cout << "\n";
    }

    // Jump to the start of the code section
    file.seekg(header.hdrsize * 16, std::ios::beg);
    size_t codeSize = std::min<size_t>(fileSize - (header.hdrsize * 16), 1024);

    std::vector<uint8_t> code(codeSize);
    file.read(reinterpret_cast<char*>(code.data()), code.size());

    std::cout << "Code Analysis (looking for INT 21h calls):\n";
    std::cout << "------------------------------------------\n";

    for (size_t i = 0; i < code.size() - 1; ++i) {
        if (code[i] == 0xCD && code[i + 1] == 0x21) {
            size_t offset = header.hdrsize * 16 + i;
            std::cout << "Found INT 21h at offset 0x" << std::hex << offset << "\n";

            // Dump surrounding bytes for context
            std::cout << "  Surrounding bytes: ";
            for (int j = -10; j < 10; ++j) {
                if ((int)i + j >= 0 && (i + j) < code.size()) {
                    std::cout << std::setw(2) << std::setfill('0') 
                              << std::hex << (int)code[i + j] << " ";
                }
            }
            std::cout << "\n";

            // Check for common DOS functions (based on previous MOV AH, XX)
            if (i >= 2 && code[i - 2] == 0xB4) {
                uint8_t fn = code[i - 1];
                std::cout << "  MOV AH, 0x" << std::hex << (int)fn << " => ";

                switch (fn) {
                    case 0x00: std::cout << "Program terminate"; break;
                    case 0x01: std::cout << "Char input with echo"; break;
                    case 0x02: std::cout << "Char output"; break;
                    case 0x09: std::cout << "Print string"; break;
                    case 0x0A: std::cout << "Buffered input"; break;
                    case 0x3C: std::cout << "Create file"; break;
                    case 0x3D: std::cout << "Open file"; break;
                    case 0x3E: std::cout << "Close file"; break;
                    case 0x3F: std::cout << "Read file"; break;
                    case 0x40: std::cout << "Write file"; break;
                    case 0x41: std::cout << "Delete file"; break;
                    case 0x4C: std::cout << "Exit program"; break;
                    default: std::cout << "Unknown function (0x" << std::hex << (int)fn << ")";
                }
                std::cout << "\n\n";
            }
        }
    }

    // Look specifically for 0x3F (file read) byte
    std::cout << "Extra: Scanning for DOS interrupt functions in raw code:\n";
    std::cout << "--------------------------------------------------\n";
    for (size_t i = 0; i < code.size(); ++i) {
        if (code[i] == 0xCD && i + 1 < code.size()) {
            uint8_t interrupt = code[i + 1];
            std::cout << "Found INT " << std::hex << (int)interrupt << "h at offset 0x" 
                      << std::hex << (header.hdrsize * 16 + i) << "\n";

            // Show some context around the byte
            std::cout << "  Context: ";
            for (int j = -10; j <= 10; ++j) {
                if ((int)i + j >= 0 && (i + j) < code.size()) {
                    if (j == 0)
                        std::cout << "[CD] ";
                    else if (j == 1)
                        std::cout << "[" << std::hex << (int)interrupt << "] ";
                    else
                        std::cout << std::setw(2) << std::setfill('0') 
                                  << std::hex << (int)code[i + j] << " ";
                }
            }
            std::cout << "\n";

            // Check for common DOS functions
            if (interrupt == 0x21 || interrupt == 0x3F) {  // Handle both 21h and 3Fh
                uint8_t fn = code[i - 1];
                std::cout << "  Purpose: ";
                switch (fn) {
                    case 0x00: std::cout << "Program terminate"; break;
                    case 0x01: std::cout << "Char input with echo"; break;
                    case 0x02: std::cout << "Char output"; break;
                    case 0x09: std::cout << "Print string"; break;
                    case 0x0A: std::cout << "Buffered input"; break;
                    case 0x0C: std::cout << "Get keystroke (no echo)"; break;
                    case 0x10: std::cout << "Set cursor position"; break;
                    case 0x11: std::cout << "Get current cursor position"; break;
                    case 0x12: std::cout << "Get video mode"; break;
                    case 0x13: std::cout << "Set video mode"; break;
                    case 0x16: std::cout << "Read keystroke (buffered)"; break;
                    case 0x17: std::cout << "Set default drive"; break;
                    case 0x1A: std::cout << "Get current disk drive"; break;
                    case 0x1C: std::cout << "Get disk free space"; break;
                    case 0x1E: std::cout << "Set file attributes"; break;
                    case 0x1F: std::cout << "Get file attributes"; break;
                    case 0x25: std::cout << "Set interrupt vector"; break;
                    case 0x29: std::cout << "Get system time"; break;
                    case 0x2C: std::cout << "Get system date"; break;
                    case 0x2F: std::cout << "Get drive parameter block"; break;
                    case 0x30: std::cout << "Terminate process"; break;
                    case 0x3C: std::cout << "Create file"; break;
                    case 0x3D: std::cout << "Open file"; break;
                    case 0x3E: std::cout << "Close file"; break;
                    case 0x3F: std::cout << "Read file"; break;
                    case 0x40: std::cout << "Write file"; break;
                    case 0x41: std::cout << "Delete file"; break;
                    case 0x4C: std::cout << "Exit program"; break;
                    default: std::cout << "Unknown function (0x" << std::hex << (int)fn << ")";
                }
                std::cout << "\n";
            }
            std::cout << "\n";
        }
    }

    file.close();
}

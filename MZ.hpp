#pragma once
#include <string>
#include <vector>
#include <cstdint>

// DOS MZ header structure
struct MZHeader {
    uint16_t signature;     // MZ
    uint16_t lastsize;     // Last page size
    uint16_t nblocks;      // Total pages
    uint16_t nreloc;       // Relocation entries
    uint16_t hdrsize;      // Header size (paragraphs)
    uint16_t minalloc;     // Min memory needed
    uint16_t maxalloc;     // Max memory needed
    uint16_t ss;           // Stack segment
    uint16_t sp;           // Stack pointer
    uint16_t checksum;     // File checksum
    uint16_t ip;           // Entry point IP
    uint16_t cs;           // Entry point CS
    uint16_t relocpos;     // Relocation table offset
    uint16_t noverlay;     // Overlay number
};

struct RelocationEntry {
    uint16_t offset;
    uint16_t segment;
};

void analyzeMZExecutable(const std::string& filepath);

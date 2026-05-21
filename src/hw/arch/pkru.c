#include <stdint.h>

void haj_wrpkru(uint32_t value) {
    uint32_t eax = value;
    uint32_t ecx = 0;
    uint32_t edx = 0;
    __asm__ volatile(
        "wrpkru"
        : "+a"(eax), "+d"(edx)
        : "c"(ecx)
        : "memory"
    );
}

uint32_t haj_rdpkru(void) {
    uint32_t eax;
    uint32_t edx;
    uint32_t ecx = 0;
    __asm__ volatile(
        "rdpkru"
        : "=a"(eax), "=d"(edx)
        : "c"(ecx)
    );
    return eax;
}

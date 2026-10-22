#ifndef FUZZ_DRIVER_H
#define FUZZ_DRIVER_H

#include <stddef.h>
#include <stdint.h>

// Provided by the libFuzzer runtime (linked in by -sanitize=fuzzer). Running the loop ourselves
// lets the harness keep its own `main` instead of the one libFuzzer would otherwise define.
int LLVMFuzzerRunDriver(int *argc, char ***argv,
                        int (*callback)(const uint8_t *data, size_t size));

#endif

#pragma once

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* opaque object to represent a translated block. */
#ifdef __cplusplus
class translation_block;
#else
typedef struct translation_block translation_block;
#endif

/* following functions must be used by QEMU plugin */

/* initialize or close plugin */
/* @out is stream for plugin output */
void plugin_init(FILE* out);
void plugin_close(void);

/* get or create a block starting at @pc, with @code of a given @size in bytes.
 * @symbol_name is name of symbol block belongs to (located @symbol_pc, with
 * size @symbol_size, code @symbol_code and located in @binary_file_path)
 */
translation_block* get_translation_block(uint64_t pc, const uint8_t* code,
                                         size_t size, const char* symbol_name,
                                         uint64_t symbol_pc, size_t symbol_size,
                                         const uint8_t* symbol_code,
                                         const char* binary_file_path);

/* block @b is executed */
void event_block_executed(translation_block* b);

/* cpus are stopped (end of program) */
void event_cpus_stopped(void);

/* following functions must be implemented by QEMU plugin */

/* return pc where current function will return to for current thread of
 * execution */
uint64_t get_callee_return_address(void);

enum architecture
{
    ARCHITECTURE_X86_64
};

/* return architecture for current guest */
enum architecture get_guest_architecture(void);

#ifdef __cplusplus
}
#endif

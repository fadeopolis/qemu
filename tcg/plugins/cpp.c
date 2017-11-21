/* Support for C++ Plugin Interface */

#include "tcg-plugin.h"

#ifdef CONFIG_TCG_PLUGIN_CPP
#include "cpp/plugin_instrumentation_api.h"
#include "disas/disas.h"

/* defined in linux-user/qemu.h */
extern const char* get_mapped_file(uint64_t addr);

/* used to retrieve tb information before and after its generation */
static translation_block** current_block_ptr;
static TCGPluginInterface* plugin_tpi;

/* pc during execution has an offset. pc used through plugin_api interface are
 * already corrected. If you read a pc directly (from memory for instance), you
 * need to correct it using following function. Has no effect if called on an
 * already corrected pc */
static uint64_t get_correct_pc(uint64_t pc)
{
    uint64_t pc_offset = 0x4000000000;
    if (pc < pc_offset)
        return pc;
    return pc - pc_offset;
}

/* code architecture dependent */
#if defined(TARGET_X86_64)
/* on x86_64, return address in on the top of stack after a call is done */
static uint64_t get_callee_return_address(void)
{
    const CPUArchState* cpu_env = tpi_current_cpu_arch(plugin_tpi);
    uint64_t stack_ptr = cpu_env->regs[R_ESP];
    return get_correct_pc(tpi_guest_load64(plugin_tpi, stack_ptr));
}

static enum architecture get_guest_architecture(void)
{
    return ARCHITECTURE_X86_64;
}
#else
#error "some functions are not implemented for current architecture"
#endif

static void on_block_exec(translation_block** b_ptr)
{
    event_block_executed(*b_ptr, get_callee_return_address());
}

static void before_gen_tb(const TCGPluginInterface* tpi)
{
    current_block_ptr = malloc(sizeof(translation_block*));

    TCGv_ptr block_t = tcg_const_ptr(current_block_ptr);

    TCGArg args[] = {GET_TCGV_PTR(block_t)};
    tcg_gen_callN(tpi->tcg_ctx, on_block_exec, TCG_CALL_DUMMY_ARG, 1, args);

    tcg_temp_free_ptr(block_t);
}

static void after_gen_tb(const TCGPluginInterface* tpi)
{
    /* tb size is only available after tb generation */
    const TranslationBlock* tb = tpi->tb;
    uint64_t pc = tb->pc;
    const uint8_t* code = (const uint8_t*)tpi_guest_ptr(tpi, pc);

    const char* symbol = "";
    const char* file = "";
    uint64_t symbol_pc = 0;
    uint64_t symbol_size = 0;
    const uint8_t* symbol_code = NULL;
    if (lookup_symbol4(pc, &symbol, &file, &symbol_pc, &symbol_size)) {
        symbol_code = (const uint8_t*)tpi_guest_ptr(tpi, symbol_pc);
    } else { // symbol_pc equals to pc in this case with lookup_symbol
        symbol_pc = 0;
    }
    /* get filename from list of mappings */
    file = get_mapped_file(pc);
    if (!file)
        file = "";

    // magic offset to correct pc
    pc = get_correct_pc(pc);
    if (symbol_pc)
        symbol_pc = get_correct_pc(symbol_pc);
    translation_block* block = get_translation_block(
        pc, code, tb->size, symbol, symbol_pc, symbol_size, symbol_code, file);
    /* patch current_block ptr */
    *current_block_ptr = block;
}

static void cpus_stopped(const TCGPluginInterface* tpi)
{
    event_cpus_stopped();

    plugin_close();
}

void tpi_init(TCGPluginInterface* tpi)
{
    TPI_INIT_VERSION(tpi);
    TPI_DECL_FUNC_1(tpi, on_block_exec, void, ptr);

    tpi->before_gen_tb = before_gen_tb;
    tpi->after_gen_tb = after_gen_tb;
    tpi->cpus_stopped = cpus_stopped;
    plugin_tpi = tpi;

    plugin_init(tpi->output, get_guest_architecture());
}

#else
void tpi_init(TCGPluginInterface* tpi)
{
    fprintf(stderr, "cpp plugin support is not activated\n");
    exit(EXIT_FAILURE);
}

#endif /* CONFIG_TCG_PLUGIN_CPP */

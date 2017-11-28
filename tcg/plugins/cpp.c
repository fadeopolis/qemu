/* Support for C++ Plugin Interface */

#include "tcg-plugin.h"

#ifdef CONFIG_TCG_PLUGIN_CPP
#include "cpp/plugin_instrumentation_api.h"

/* defined in linux-user/qemu.h */
extern bool get_mapped_file(uint64_t addr, const char** name,
                            uint64_t* base_addr);

/* used to retrieve tb information before and after its generation */
static translation_block** current_block_ptr;
static TCGPluginInterface* plugin_tpi;

/* code architecture dependent */
#if defined(TARGET_X86_64) || defined(TARGET_I386)
/* on i386/x86_64, return address in on the top of stack after a call is done */
static uint64_t get_callee_return_address(void)
{
    const CPUArchState* cpu_env = tpi_current_cpu_arch(plugin_tpi);
    uint64_t stack_ptr = cpu_env->regs[R_ESP];
#if defined(TARGET_X86_64)
    return tpi_guest_load64(plugin_tpi, stack_ptr);
#elif defined(TARGET_I386)
    return tpi_guest_load32(plugin_tpi, stack_ptr);
#endif
}

#if defined(TARGET_X86_64)
static enum architecture current_arch = ARCHITECTURE_X86_64;
#elif defined(TARGET_I386)
static enum architecture current_arch = ARCHITECTURE_I386;
#endif

#elif defined(TARGET_ARM) || defined(TARGET_AARCH64)
static uint64_t get_callee_return_address(void)
{
    /* The return address for a function on ARM is in 32b reg r14
       or 64b xreg 30.
       Clear low bit which is used for legacy 13/32 support.
    */
    const CPUArchState *cpu_env = tpi_current_cpu_arch(plugin_tpi);
    return cpu_env->aarch64 ? cpu_env->xregs[30]:
        (cpu_env->regs[14] & (~(uint64_t)0 << 1));
}

#if defined(TARGET_AARCH64)
static enum architecture current_arch = ARCHITECTURE_AARCH64;
#elif defined(TARGET_ARM)
static enum architecture current_arch = ARCHITECTURE_ARM;
#endif

#else
#error "some functions are not implemented for current architecture"
#endif

static enum architecture get_guest_architecture(void)
{
    return current_arch;
}

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

    const char* file = NULL;
    uint64_t load_address = 0;

    get_mapped_file(pc, &file, &load_address);

    translation_block* block =
        get_translation_block(pc, code, tb->size, file, load_address);
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

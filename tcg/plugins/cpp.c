/* Support for C++ Plugin Interface */

#include "tcg-plugin.h"

#include "cpp/plugin_qemu_api.h"
#include "disas/disas.h"

static void on_block_exec(translation_block** b_ptr)
{
    event_block_executed(*b_ptr);
}

/* used to retrieve tb information before and after its generation */
static translation_block** current_block_ptr;

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
    }

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

    plugin_init(tpi->output);
}

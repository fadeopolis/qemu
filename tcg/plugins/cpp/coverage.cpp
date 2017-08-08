#include "plugin_api.h"

#include <inttypes.h>
#include <iostream>
#include <map>
#include <unordered_map>
#include <unordered_set>

class plugin_coverage : public plugin
{
public:
    plugin_coverage()
        : plugin("coverage", "print instructions coverage for known symbols")
    {
    }

    void on_block_enter(translation_block& b) override
    {
        symbol& s = b.symbol();
        if (s.name().empty())
            return;
        ++blocks_[&b];
        symbols_.insert(&s);
    }

    void on_program_end() override
    {
        /* create a map, that, for each instruction, count number of hits */
        std::unordered_map<uint64_t /* pc */, uint64_t /* counter */> hits;
        for (const auto& pair : blocks_) {
            translation_block& b = *(pair.first);
            uint64_t number_hits = pair.second;
            for (const auto& i : b.instructions()) {
                hits[i->pc()] += number_hits;
            }
        }

        /* create ordered map (pc) of symbols */
        std::map<uint64_t /* pc */, symbol*> ordered_symbols;
        for (const auto& s : symbols_) {
            ordered_symbols[s->pc()] = s;
        }

        /* dump symbol */
        for (const auto& pair : ordered_symbols) {
            symbol& s = *pair.second;
            dump_symbol_coverage(s, hits);
        }
    }

    void dump_symbol_coverage(
        symbol& s,
        std::unordered_map<uint64_t /* pc */, uint64_t /* counter */>& hits)
    {
        csh handle = instruction::get_capstone_handle();
        cs_insn* inst = cs_malloc(handle);

        uint64_t pc = s.pc();
        size_t size = s.size();
        const uint8_t* code = s.code();

        std::cerr << "symbol '" << s.name() << "' from file '"
                  << s.file().path() << "'\n";
        // disassemble whole symbol
        while (cs_disasm_iter(handle, &code, &size, &pc, inst)) {
            uint64_t count = hits[inst->address];

            fprintf(stderr, "%s%8" PRIu64 "%s | 0x%" PRIx64 ":\t %s%s\t %s%s\n",
                    count ? "\033[1;32m" : "\033[1;30m", count, "\033[1;30m",
                    inst->address, count ? "\033[1;32m" : "\033[1;30m",
                    inst->mnemonic, inst->op_str, "\033[0;37m");
        }
        std::cerr << "--------------------------------------------\n";
        cs_free(inst, 1);
    }

private:
    std::unordered_map<translation_block*, uint64_t /* counter */> blocks_;
    std::unordered_set<symbol*> symbols_;
};

REGISTER_PLUGIN(plugin_coverage);

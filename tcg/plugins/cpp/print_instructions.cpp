#include "plugin_api.h"

#include <iostream>

class plugin_print_instructions : public plugin
{
public:
    plugin_print_instructions()
        : plugin("print_instructions",
                 "print instructions block by block when executing")
    {
    }

    void on_program_start() override { std::cerr << "start program\n"; }

    void on_block_transition(translation_block& b, translation_block*,
                             translation_block::block_transition_type type,
                             translation_block*) override
    {
        std::cerr << "-----------------------------------\n";
        if (!b.current_symbol()->name().empty())
            std::cerr << "from symbol '" << b.current_symbol()->name()
                      << "' in file '" << b.current_symbol()->file().path()
                      << "'\n";
        std::cerr << "block enter "
                  << "0x" << std::hex << b.pc() << std::dec << '\n';
        std::cerr << "block has " << b.instructions().size()
                  << " instructions\n";

        using tt = translation_block::block_transition_type;
        switch (type) {
        case tt::START:
            std::cerr << "reached by program start\n";
            break;
        case tt::CALL:
            std::cerr << "reached by call\n";
            break;
        case tt::RETURN:
            std::cerr << "reached by return\n";
            break;
        case tt::SEQUENTIAL:
            std::cerr << "reached by sequential execution\n";
            break;
        case tt::JUMP:
            std::cerr << "reached by jump\n";
            break;
        }
    }

    void on_instruction_exec(translation_block&, instruction& i) override
    {
        std::cerr << "exec 0x" << std::hex << i.pc() << std::dec << " "
                  << i.str() << '\n';
        const source_line* line = i.line();
        if (line) {
            std::cerr << "// from file " << line->file().path() << ":"
                      << line->number() << ": " << line->line() << '\n';
        }
    }

    void on_block_exit(translation_block& b) override
    {
        std::cerr << "block exit  "
                  << "0x" << std::hex << b.pc() << std::dec << '\n';
    }

    void on_program_end() override { std::cerr << "end program\n"; }

private:
};

REGISTER_PLUGIN(plugin_print_instructions);

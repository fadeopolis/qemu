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

    void on_block_enter(translation_block& b) override
    {
        std::cerr << "-----------------------------------\n";
        if (!b.symbol().name().empty())
            std::cerr << "from symbol '" << b.symbol().name() << "' in file '"
                      << b.symbol().file().path() << "'\n";
        std::cerr << "block enter "
                  << "0x" << std::hex << b.pc() << std::dec << '\n';
        std::cerr << "block has " << b.instructions().size()
                  << " instructions\n";

        if (next_block_pc_ == b.pc())
            std::cerr << "reached by sequential execution\n";
        else
            std::cerr << "reached by jump\n";
        next_block_pc_ = b.pc() + b.size();
    }

    void on_instruction_exec(translation_block&, instruction& i) override
    {
        std::cerr << "exec " << i.str() << '\n';
    }

    void on_block_exit(translation_block& b) override
    {
        std::cerr << "block exit  "
                  << "0x" << std::hex << b.pc() << std::dec << '\n';
    }

    void on_program_end() override { std::cerr << "end program\n"; }

private:
    uint64_t next_block_pc_ = 0;
};

REGISTER_PLUGIN(plugin_print_instructions);

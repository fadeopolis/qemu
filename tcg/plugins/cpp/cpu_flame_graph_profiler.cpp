#include "plugin_api.h"

#include <map>

class plugin_cpu_flame_graph_profiler : public plugin
{
public:
    using sym_call_stack = std::vector<const symbol*>;

    plugin_cpu_flame_graph_profiler()
        : plugin(
              "cpu_flame_graph_profiler",
              "generate a cpu flame graph compatible output from program exec")
    {
    }

    void on_block_enter(translation_block& b) override
    {
        const uint64_t num_inst_sample = 10000;
        uint64_t num_inst_block = b.instructions().size();
        count_inst += num_inst_block;
        if (count_inst < num_inst_sample)
            return;

        count_inst = count_inst % num_inst_sample;
        const instruction* current_inst = b.instructions().front();
        call_stack cs = get_call_stack();
        cs.emplace_back(current_inst);

        sym_call_stack sym_cs = call_stack_to_sym_call_stack(cs);
        ++call_stack_count[sym_cs];
    }

    virtual void on_program_end() override
    {
        for (const auto& p : call_stack_count) {
            const sym_call_stack& cs = p.first;
            uint64_t count = p.second;
            dump_flame_graph_stack(cs, count);
        }
    }

private:
    sym_call_stack call_stack_to_sym_call_stack(call_stack& cs)
    {
        sym_call_stack res;
        res.reserve(cs.size());
        for (const instruction* i : cs) {
            const symbol* s = i->current_symbol();
            res.emplace_back(s);
        }
        return res;
    }

    void dump_flame_graph_stack(const sym_call_stack& cs, uint64_t count)
    {
        fprintf(output(), "all");
        for (const symbol* sym_ptr : cs) {
            const symbol& sym = *sym_ptr;
            std::string sym_name = sym.name();
            if (sym_name.empty()) {
                sym_name = "[unknown]";
            }
            fprintf(output(), ";%s", sym_name.c_str());
        }
        fprintf(output(), " %lu\n", count);
    }

    uint64_t count_inst = 0;
    std::map<sym_call_stack, uint64_t /* count */> call_stack_count;
};

REGISTER_PLUGIN(plugin_cpu_flame_graph_profiler);

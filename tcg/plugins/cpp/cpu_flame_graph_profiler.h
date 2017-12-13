#pragma once

#include "plugin_api.h"

#include <map>

class plugin_cpu_flame_graph_profiler : public plugin
{
public:
    using sym_call_stack = std::vector<const symbol*>;

    plugin_cpu_flame_graph_profiler(const uint64_t num_inst_sample = 1000)
        : plugin(
              "cpu_flame_graph_profiler",
              "generate a cpu flame graph compatible output from program exec"),
          num_inst_sample_(num_inst_sample)
    {
    }

    void on_block_executed(translation_block& b,
                           const std::vector<memory_access>&) override
    {
        uint64_t num_inst_block = b.instructions().size();
        count_inst += num_inst_block;
        if (count_inst < num_inst_sample_)
            return;

        count_inst = count_inst % num_inst_sample_;
        const instruction* current_inst = b.instructions().front();
        call_stack cs = get_call_stack();
        cs.emplace_back(current_inst);

        sym_call_stack sym_cs = call_stack_to_sym_call_stack(cs);
        ++call_stack_count_[sym_cs];
    }

    const std::map<sym_call_stack, uint64_t>& call_stack_count() const
    {
        return call_stack_count_;
    }

    std::string get_flame_graph()
    {
        std::string res;
        for (const auto& p : call_stack_count_) {
            const sym_call_stack& cs = p.first;
            uint64_t count = p.second;
            res += flame_graph_stack(cs, count);
            res += '\n';
        }
        return res;
    }

    virtual void on_program_end() override
    {
        fprintf(output(), "%s", get_flame_graph().c_str());
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

    std::string flame_graph_stack(const sym_call_stack& cs, uint64_t count)
    {
        std::string res;
        res += "all";
        for (const symbol* sym_ptr : cs) {
            const symbol& sym = *sym_ptr;
            std::string sym_name = sym.name();
            if (sym_name.empty())
                sym_name = "[unknown]";
            res += ";";
            res += sym_name;
        }
        res += " ";
        res += std::to_string(count);
        return res;
    }

    uint64_t num_inst_sample_ = 0;
    uint64_t count_inst = 0;
    std::map<sym_call_stack, uint64_t /* count */> call_stack_count_;
};

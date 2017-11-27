#include "plugin_api.h"

#include <algorithm>
#include <numeric>
#include <unordered_map>
#include <vector>

class plugin_count_instructions : public plugin
{
public:
    plugin_count_instructions()
        : plugin("count_instructions", "count instructions and print summary")
    {
    }

    void on_instruction_exec(translation_block&, instruction& i) override
    {
        /* we could count only block execution, and at the end summarizes
         * instructions for each of them, much more optimized */
        const auto& cs = i.capstone_inst();
        ++instructions_count_[cs.id];
    }

    void on_program_end() override
    {
        uint64_t total = std::accumulate(
            instructions_count_.begin(), instructions_count_.end(), 0,
            [](auto value, const auto& p) { return value + p.second; });

        fprintf(output(), "executed %lu instructions\n", total);

        std::vector<std::pair<uint64_t, uint64_t>> vec_inst;

        vec_inst.insert(vec_inst.end(), instructions_count_.begin(),
                        instructions_count_.end());
        std::sort(vec_inst.begin(), vec_inst.end(),
                  [](const auto& p1, const auto& p2) {
                      return p1.second > p2.second;
                  });

        for (const auto& it : vec_inst) {
            uint64_t id = it.first;
            uint64_t count = it.second;
            float percentage = count * 100.0 / total;
            const std::string& inst_str =
                cs_insn_name(instruction::get_capstone_handle(), id);
            fprintf(output(), "instr %s executed %lu times (percentage %f)\n",
                    inst_str.c_str(), count, percentage);
        }
    }

private:
    std::unordered_map<uint64_t /* id */, uint64_t /* count */>
        instructions_count_;
};

REGISTER_PLUGIN(plugin_count_instructions);

#include "plugin_qemu_api.h"

#include "plugin_api.h"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

// RAII object to use capstone
class capstone
{
public:
    capstone(const capstone&) = delete;
    capstone& operator=(const capstone&) = delete;

    csh handle() const { return handle_; }

    static capstone& get()
    {
        static capstone c;
        return c;
    }

private:
    capstone()
    {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) {
            fprintf(stderr, "FATAL: error opening capstone library\n");
            exit(EXIT_FAILURE);
        }
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    }

    ~capstone() { cs_close(&handle_); }

    csh handle_;
};

// split a string @str in token delimited by @delim
static std::vector<std::string> split_string(const std::string& str, char delim)
{
    std::stringstream ss(str);
    std::string item;
    std::vector<std::string> res;
    while (std::getline(ss, item, delim)) {
        res.emplace_back(std::move(item));
    }
    return res;
}

csh instruction::get_capstone_handle()
{
    return capstone::get().handle();
}

// manager for plugins
class plugin_manager
{
public:
    plugin_manager(const plugin_manager&) = delete;
    plugin_manager& operator=(const plugin_manager&) = delete;

    static plugin_manager& get()
    {
        static plugin_manager p;
        return p;
    }

    // get or create a translation block
    translation_block&
    get_translation_block(uint64_t pc, const uint8_t* code, size_t size,
                          const std::string& symbol_name, uint64_t symbol_pc,
                          size_t symbol_size, const uint8_t* symbol_code,
                          const std::string& binary_file_path)
    {
        auto it = blocks_.find(pc);
        if (it != blocks_.end()) {
            return it->second;
        }

        binary_file& file = get_binary_file(binary_file_path);
        symbol& s =
            get_symbol(symbol_name, symbol_pc, symbol_size, symbol_code, file);

        translation_block& b =
            blocks_
                .emplace(std::piecewise_construct, std::forward_as_tuple(pc),
                         std::forward_as_tuple(pc, size, s))
                .first->second;
        // add instructions for block
        disassemble_block(b, pc, code, size);
        return b;
    }

    // register plugin @p as available
    void register_plugin(plugin& p)
    {
        const auto& it = available_plugins_.emplace(p.name(), &p);
        if (!it.second) {
            fprintf(out_, "FATAL: plugin %s was already registered\n",
                    p.name().c_str());
            exit(EXIT_FAILURE);
        }
    }

    void event_program_start()
    {
        activate_plugins();

        for (const auto& p : plugins_) {
            p->on_program_start();
        }
    }

    void event_block_executed(translation_block& b)
    {
        for (const auto& p : plugins_) {
            p->on_block_enter(b);
        }
        for (const auto& i : b.instructions()) {
            for (const auto& p : plugins_) {
                p->on_instruction_exec(b, *i);
            }
        }
        for (const auto& p : plugins_) {
            p->on_block_exit(b);
        }
    }

    void event_cpus_stopped()
    {
        for (const auto& p : plugins_) {
            p->on_program_end();
        }
    }

    void set_out(FILE* out) { out_ = out; }
private:
    plugin_manager() {}

    // get or create a binary file
    binary_file& get_binary_file(const std::string& path)
    {
        auto it = files_.find(path);
        if (it != files_.end()) {
            return it->second;
        }

        return files_.emplace(path, path).first->second;
    }

    // get or create a symbol (adds it to its file)
    symbol& get_symbol(const std::string& name, uint64_t pc, size_t size,
                       const uint8_t* code, binary_file& file)
    {
        auto it = symbols_.find(pc);
        if (it != symbols_.end()) {
            return it->second;
        }

        symbol& s =
            symbols_
                .emplace(std::piecewise_construct, std::forward_as_tuple(pc),
                         std::forward_as_tuple(name, pc, size, code, file))
                .first->second;
        file.add_symbol(s);
        return s;
    }

    // get or create an instruction
    instruction& get_instruction(uint64_t pc, cs_insn& capstone_inst)
    {
        auto it = instructions_.find(pc);
        if (it != instructions_.end()) {
            return it->second;
        }

        instruction& inst =
            instructions_.emplace(pc, capstone_inst).first->second;
        return inst;
    }

    // get or create a capstone instruction
    cs_insn& get_capstone_instruction(uint64_t pc)
    {
        auto it = capstone_instructions_.find(pc);
        if (it != capstone_instructions_.end()) {
            return *(it->second);
        }

        std::unique_ptr<cs_insn, void (*)(cs_insn*)> insn(
            cs_malloc(capstone::get().handle()),
            [](cs_insn* inst) { cs_free(inst, 1); });
        return *(
            capstone_instructions_.emplace(pc, std::move(insn)).first->second);
    }

    // disassemble instructions of a given block @b and and them to it
    void disassemble_block(translation_block& b, uint64_t pc,
                           const uint8_t* code, size_t size)
    {
        cs_insn* insn = &get_capstone_instruction(pc);
        csh handle = capstone::get().handle();
        while (cs_disasm_iter(handle, &code, &size, &pc, insn)) {
            instruction& inst = get_instruction(insn->address, *insn);
            b.add_instruction(inst);
            insn = &get_capstone_instruction(pc);
        }
    }

    void list_available_plugins()
    {
        fprintf(out_, "plugins available are:\n");
        for (const auto& pair : available_plugins_) {
            const plugin& p = *pair.second;
            fprintf(out_, "- %s: %s\n", p.name().c_str(),
                    p.description().c_str());
        }
    }

    void activate_plugins()
    {
        const char* plugins_list_str = getenv(env_var_plugins_name_.c_str());

        if (!plugins_list_str) {
            fprintf(out_, "FATAL: env var %s must be set to list of active "
                          "plugins (comma separated)\n",
                    env_var_plugins_name_.c_str());
            list_available_plugins();
            exit(EXIT_FAILURE);
        }

        std::vector<std::string> plugins_list_vec =
            split_string(plugins_list_str, ',');
        std::set<std::string> plugins_list(plugins_list_vec.begin(),
                                           plugins_list_vec.end());

        for (const auto& name : plugins_list) {
            const auto& it = available_plugins_.find(name);
            if (it == available_plugins_.end()) {
                fprintf(out_, "FATAL: plugin %s is unknown\n", name.c_str());
                list_available_plugins();
                exit(EXIT_FAILURE);
            }
            plugins_.push_back(it->second);
        }
    }

    FILE* out_ = stderr;
    std::unordered_map<uint64_t /* pc */,
                       std::unique_ptr<cs_insn, void (*)(cs_insn*)>>
        capstone_instructions_;
    std::unordered_map<uint64_t /* pc */, instruction> instructions_;
    std::unordered_map<uint64_t /* pc */, translation_block> blocks_;
    std::unordered_map<uint64_t /* pc */, symbol> symbols_;
    std::unordered_map<std::string /* name */, binary_file> files_;
    std::map<std::string /* name */, plugin*> available_plugins_;
    std::vector<plugin*> plugins_; /* active */
    static const std::string env_var_plugins_name_;
};

const std::string plugin_manager::env_var_plugins_name_ = "TCG_PLUGIN_CPP";

void plugin_init(FILE* out)
{
    plugin_manager::get().set_out(out);
    plugin_manager::get().event_program_start();
}

void plugin_close()
{
}

translation_block* get_translation_block(uint64_t pc, const uint8_t* code,
                                         size_t size, const char* symbol_name,
                                         uint64_t symbol_pc, size_t symbol_size,
                                         const uint8_t* symbol_code,
                                         const char* binary_file_path)
{
    translation_block& b = plugin_manager::get().get_translation_block(
        pc, code, size, symbol_name, symbol_pc, symbol_size, symbol_code,
        binary_file_path);
    return &b;
}

void event_block_executed(translation_block* b)
{
    plugin_manager::get().event_block_executed(*b);
}

void event_cpus_stopped(void)
{
    plugin_manager::get().event_cpus_stopped();
}

void register_plugin(plugin& p)
{
    plugin_manager::get().register_plugin(p);
}

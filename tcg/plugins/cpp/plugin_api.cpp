#include "plugin_instrumentation_api.h"

#include "plugin_api.h"

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <unistd.h>
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

    static void set_guest_architecture(enum architecture arch)
    {
        guest_architecture = arch;
    }

private:
    capstone()
    {
        cs_arch arch;
        cs_mode mode;

        switch (guest_architecture) {
        case architecture::ARCHITECTURE_X86_64:
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        case architecture::ARCHITECTURE_UNKNOWN:
            fprintf(stderr, "FATAL: capstone architecture was not set\n");
            exit(EXIT_FAILURE);
            break;
        }

        if (cs_open(arch, mode, &handle_) != CS_ERR_OK) {
            fprintf(stderr, "FATAL: error opening capstone library\n");
            exit(EXIT_FAILURE);
        }
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }

    ~capstone() { cs_close(&handle_); }

    csh handle_;
    static enum architecture guest_architecture;
};

enum architecture capstone::guest_architecture =
    architecture::ARCHITECTURE_UNKNOWN;

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

class call_stack_entry
{
public:
    call_stack_entry(const instruction* caller, uint64_t expected_next_pc,
                     translation_block* tb)
        : caller_(caller), expected_next_pc_(expected_next_pc), tb_(tb)
    {
    }

    const instruction* caller() const { return caller_; }
    uint64_t expected_next_pc() const { return expected_next_pc_; }
    translation_block* tb() const { return tb_; }

private:
    const instruction* caller_;
    uint64_t expected_next_pc_;
    translation_block* tb_;
};

/* keeps track of block chaining.
 * maintain a call_stack for all blocks executed. */
class block_chain_recorder
{
public:
    block_chain_recorder() { call_stack_.reserve(1000); }

    translation_block::block_transition_type
    on_block_exec(translation_block& b, translation_block*& caller,
                  uint64_t potential_callee_return_address)
    {
        last_executed_block_ = current_block_;
        current_block_ = &b;

        return track_stack(b, last_executed_block_, caller,
                           potential_callee_return_address);
    }

    translation_block* get_last_block_executed() const
    {
        return last_executed_block_;
    }

    call_stack get_call_stack() const
    {
        call_stack cs;
        cs.reserve(call_stack_.size() + 1); /* +1 to push current instruction */
        for (const auto& cs_entry : call_stack_) {
            cs.emplace_back(cs_entry.caller());
        }
        return cs;
    }

    uint64_t get_current_symbol_pc() { return current_symbol_start_pc_; }

private:
    translation_block::block_transition_type
    track_stack(translation_block& b, translation_block* last_executed_block,
                translation_block*& caller,
                uint64_t potential_callee_return_address)
    {
        uint64_t current_pc = b.pc();

        using tt = translation_block::block_transition_type;

        if (!last_executed_block) { /* first time */
            current_symbol_start_pc_ = current_pc;
            return tt::START;
        }

        uint64_t expected_block_pc =
            last_executed_block->pc() + last_executed_block->size();

        if (expected_block_pc == current_pc) /* linear execution */
            return tt::SEQUENTIAL;

        /* check if we returned, walk the stack to find expected pc */
        for (auto it = call_stack_.end(); it != call_stack_.begin(); --it) {
            uint64_t expected_pc = it->expected_next_pc();
            if (expected_pc == current_pc) /* this is a function return */
            {
                caller = it->tb();
                current_symbol_start_pc_ = caller->current_symbol()->pc();
                call_stack_.erase(it, call_stack_.end());
                return tt::RETURN;
            }
        }

        uint64_t return_address = potential_callee_return_address;

        if (return_address != expected_block_pc) {
            /* this is a simple jump */
            return tt::JUMP;
        }

        /* this is a call, because return address was stored */
        caller = last_executed_block;
        current_symbol_start_pc_ = current_pc;
        call_stack_.emplace_back(last_executed_block->instructions().back(),
                                 expected_block_pc, last_executed_block);
        return tt::CALL;
    }

    std::vector<call_stack_entry> call_stack_;
    translation_block* last_executed_block_ = nullptr;
    translation_block* current_block_ = nullptr;
    uint64_t current_symbol_start_pc_ = 0;
};

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
        std::lock_guard<std::mutex> mt_lock(mt_mutex_);

        auto it = blocks_mapping_.find(pc);
        if (it != blocks_mapping_.end()) {
            return *it->second;
        }

        binary_file& file = get_binary_file(binary_file_path);
        files_mapping_[pc] = &file;

        uint64_t new_id = block_id_;
        ++block_id_;

        translation_block& b =
            blocks_
                .emplace(std::piecewise_construct,
                         std::forward_as_tuple(new_id),
                         std::forward_as_tuple(new_id, pc, size))
                .first->second;

        blocks_mapping_.emplace(pc, &b);
        // add instructions for block
        disassemble_block(b, pc, code, size);

        if (symbol_pc != 0) /* symbol is known */
        {
            symbol& s = get_symbol(symbol_name, symbol_pc, symbol_size,
                                   symbol_code, file);
            b.set_current_symbol(s);
        }

        return b;
    }

    // get or create an instruction
    instruction& get_instruction(uint64_t pc,
                                 instruction::capstone_inst_ptr capstone_inst)
    {
        auto it = instructions_mapping_.find(pc);
        if (it != instructions_mapping_.end()) {
            return *it->second;
        }

        uint64_t new_id = instruction_id_;
        ++instruction_id_;

        instruction& inst =
            instructions_
                .emplace(std::piecewise_construct,
                         std::forward_as_tuple(new_id),
                         std::forward_as_tuple(new_id, std::move(capstone_inst),
                                               pc_to_lines_[pc]))
                .first->second;
        instructions_mapping_.emplace(pc, &inst);
        return inst;
    }

    call_stack get_call_stack()
    {
        return get_current_thread_bc().get_call_stack();
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

    block_chain_recorder& get_current_thread_bc()
    {
        return bc_recorders_[std::this_thread::get_id()];
    }

    void event_block_executed(translation_block& b,
                              uint64_t potential_callee_return_address)
    {
        std::lock_guard<std::mutex> mt_lock(mt_mutex_);

        translation_block* caller = nullptr;
        /* maintain call stack and detect call/ret */
        block_chain_recorder& bc_recorder = get_current_thread_bc();
        translation_block::block_transition_type transition_type =
            bc_recorder.on_block_exec(b, caller,
                                      potential_callee_return_address);

        /* correct symbol by using call stack */
        uint64_t current_symbol_pc = bc_recorder.get_current_symbol_pc();
        if (!b.current_symbol() ||
            b.current_symbol()->pc() != current_symbol_pc) // correct symbol
        {
            binary_file& file = *files_mapping_[current_symbol_pc];
            symbol& s = get_symbol("", current_symbol_pc, 0, nullptr, file);
            b.set_current_symbol(s);
        }

        /* block transition */
        for (const auto& p : plugins_) {
            p->on_block_transition(b, bc_recorder.get_last_block_executed(),
                                   transition_type, caller);
        }

        /* block execution */
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
        auto it = binary_files_.find(path);
        if (it != binary_files_.end()) {
            return it->second;
        }

        std::string error;
        if (!path.empty() && !read_dwarf(path, error)) {
            fprintf(stderr, "WARNING: error reading dwarf for file %s: %s\n",
                    path.c_str(), error.c_str());
        }

        return binary_files_.emplace(path, path).first->second;
    }

    // get or create a source file
    source_file& get_source_file(const std::string& path)
    {
        auto it = source_files_.find(path);
        if (it != source_files_.end())
            return it->second;
        source_file& file = source_files_.emplace(path, path).first->second;
        return file;
    }

    // get or create a symbol (adds it to its file)
    symbol& get_symbol(const std::string& name, uint64_t pc, size_t size,
                       const uint8_t* code, binary_file& file)
    {
        auto it = symbols_mapping_.find(pc);
        if (it != symbols_mapping_.end()) {
            return *it->second;
        }

        uint64_t new_id = symbol_id_;
        ++symbol_id_;

        symbol& s =
            symbols_
                .emplace(
                    std::piecewise_construct, std::forward_as_tuple(new_id),
                    std::forward_as_tuple(new_id, name, pc, size, code, file))
                .first->second;
        symbols_mapping_.emplace(pc, &s);
        file.add_symbol(s);
        return s;
    }

    // disassemble instructions of a given block @b and and them to it
    void disassemble_block(translation_block& b, uint64_t pc,
                           const uint8_t* code, size_t size)
    {
        instruction::capstone_inst_ptr insn =
            instruction::get_new_capstone_instruction();
        csh handle = capstone::get().handle();
        while (cs_disasm_iter(handle, &code, &size, &pc, insn.get())) {
            uint64_t i_pc = insn->address;
            instruction& inst = get_instruction(i_pc, std::move(insn));
            b.add_instruction(inst);
            insn = instruction::get_new_capstone_instruction();
        }
    }

    /* read and record cu source files info */
    bool read_debug_cu(Dwarf_Die cu, std::string& error)
    {
        Dwarf_Line* lines;
        Dwarf_Signed count;
        Dwarf_Error de;

        if (dwarf_srclines(cu, &lines, &count, &de) != DW_DLV_OK) {
            error = std::string("read_debug_cu|get_src: ") + dwarf_errmsg(de);
            return false;
        }

        Dwarf_Addr low_pc = 0;
        Dwarf_Addr high_pc = 0;
        dwarf_lowpc(cu, &low_pc, &de);
        if (dwarf_highpc(cu, &high_pc, &de) != DW_DLV_OK) {
            /* high_pc is an offset instead of absolute address */
            high_pc = low_pc + high_pc;
        }

        Dwarf_Addr prev_address = 0;
        const source_line* prev_source_line = nullptr;

        auto register_address = [&](Dwarf_Addr current, Dwarf_Addr prev,
                                    const source_line* prev_line) {
            if (!prev || !prev_line)
                return;
            for (auto a = prev_address; a < current; ++a) {
                if (pc_to_lines_[a] == nullptr)
                    pc_to_lines_[a] = prev_line;
            }
        };

        for (Dwarf_Signed i = 0; i < count; ++i) {
            Dwarf_Addr address = 0;
            Dwarf_Unsigned lineno = 0;
            char* file = nullptr;
            Dwarf_Line line = lines[i];

            if (dwarf_lineaddr(line, &address, &de) != DW_DLV_OK ||
                dwarf_lineno(line, &lineno, &de) != DW_DLV_OK ||
                dwarf_linesrc(line, &file, &de) != DW_DLV_OK) {
                error =
                    std::string("read_debug_cu|read_line: ") + dwarf_errmsg(de);
                return false;
            }

            register_address(address, prev_address, prev_source_line);

            source_file& source = get_source_file(file);
            prev_address = address;
            prev_source_line = &source.get_line(lineno);
        }

        // register address for last instruction
        register_address(high_pc, prev_address, prev_source_line);
        return true;
    }

    /* read dwarf file @file */
    bool read_dwarf(const std::string& file, std::string& error)
    {
        int fd = open(file.c_str(), O_RDONLY);
        if (fd < 0) {
            error = strerror(errno);
            return false;
        }

        Dwarf_Debug dbg;
        Dwarf_Error de;
        Dwarf_Unsigned cu_offset = 0;

        auto cleanup = [&]() {
            close(fd);
            dwarf_finish(dbg, &de);
        };

        if (dwarf_init(fd, DW_DLC_READ, nullptr, nullptr, &dbg, &de) !=
            DW_DLV_OK) {
            error = std::string("dwarf_init: ") + dwarf_errmsg(de);
            cleanup();
            return false;
        }

        while (dwarf_next_cu_header(dbg, nullptr, nullptr, nullptr, nullptr,
                                    &cu_offset, &de) == DW_DLV_OK) {
            Dwarf_Die die = nullptr;
            Dwarf_Die ret_die = nullptr;
            Dwarf_Half tag;
            while (dwarf_siblingof(dbg, die, &ret_die, &de) == DW_DLV_OK) {
                die = ret_die;
                if (dwarf_tag(die, &tag, &de) == DW_DLV_OK &&
                    tag == DW_TAG_compile_unit) {
                    if (!read_debug_cu(die, error)) {
                        cleanup();
                        return false;
                    }
                }
            }
        }

        cleanup();
        return true;
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

    uint64_t instruction_id_ = 0;
    uint64_t block_id_ = 0;
    uint64_t symbol_id_ = 0;
    std::unordered_map<uint64_t /* id */, instruction> instructions_;
    std::unordered_map<uint64_t /* id */, translation_block> blocks_;
    std::unordered_map<uint64_t /* id */, symbol> symbols_;
    std::unordered_map<uint64_t /* pc */, instruction*> instructions_mapping_;
    std::unordered_map<uint64_t /* pc */, translation_block*> blocks_mapping_;
    std::unordered_map<uint64_t /* pc */, symbol*> symbols_mapping_;
    std::unordered_map<uint64_t /* pc */, binary_file*> files_mapping_;

    std::unordered_map<std::string /* name */, binary_file> binary_files_;
    std::unordered_map<std::string /* path */, source_file> source_files_;
    std::unordered_map<uint64_t /* pc */, const source_line*> pc_to_lines_;
    std::map<std::string /* name */, plugin*> available_plugins_;
    std::vector<plugin*> plugins_; /* active */
    static const std::string env_var_plugins_name_;
    std::unordered_map<std::thread::id, block_chain_recorder> bc_recorders_;
    std::mutex mt_mutex_;
};

instruction::capstone_inst_ptr instruction::get_new_capstone_instruction()
{
    instruction::capstone_inst_ptr insn(
        cs_malloc(capstone::get().handle()),
        [](cs_insn* inst) { cs_free(inst, 1); });
    return insn;
}

instruction&
plugin::get_instruction(uint64_t pc,
                        instruction::capstone_inst_ptr capstone_inst)
{
    return plugin_manager::get().get_instruction(pc, std::move(capstone_inst));
}

call_stack plugin::get_call_stack()
{
    return plugin_manager::get().get_call_stack();
}

const std::string plugin_manager::env_var_plugins_name_ = "TCG_PLUGIN_CPP";

void plugin_init(FILE* out, enum architecture arch)
{
    plugin_manager::get().set_out(out);
    capstone::set_guest_architecture(arch);
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

void event_block_executed(translation_block* b,
                          uint64_t potential_callee_return_address)
{
    plugin_manager::get().event_block_executed(*b,
                                               potential_callee_return_address);
}

void event_cpus_stopped(void)
{
    plugin_manager::get().event_cpus_stopped();
}

void register_plugin(plugin& p)
{
    plugin_manager::get().register_plugin(p);
}

#pragma once

#include <capstone/capstone.h>
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <vector>

class binary_file;

// a symbol in binary @file with given @name, at address @pc, @size bytes, with
// @code
class symbol
{
public:
    symbol(const std::string& name, uint64_t pc, size_t size,
           const uint8_t* code, binary_file& file)
        : name_(name), pc_(pc), size_(size), code_(code), file_(file)
    {
    }

    const std::string& name() const { return name_; }
    uint64_t pc() const { return pc_; }
    size_t size() const { return size_; }
    const uint8_t* code() const { return code_; }
    binary_file& file() { return file_; }
private:
    std::string name_;
    uint64_t pc_;
    size_t size_;
    const uint8_t* code_;
    binary_file& file_;
};

// a binary file at @path references several symbols
class binary_file
{
public:
    binary_file(const std::string& path) : path_(path) {}

    void add_symbol(symbol& s) { symbols_.emplace_back(&s); }

    const std::string& path() const { return path_; }
    const std::vector<symbol*>& symbols() const { return symbols_; }
private:
    std::string path_;
    std::vector<symbol*> symbols_;
};

// a single instruction in the program, one per pc
class instruction
{
public:
    instruction(const cs_insn& capstone_inst) : capstone_inst_(capstone_inst) {}

    uint64_t pc() const { return capstone_inst_.address; }
    const std::string str() const
    {
        return capstone_inst_.mnemonic + std::string(" ") +
               capstone_inst_.op_str;
    }
    size_t size() const { return capstone_inst_.size; }
    const cs_insn& capstone_inst() const { return capstone_inst_; }
    static csh get_capstone_handle();

private:
    const cs_insn& capstone_inst_;
};

// a sequence of instruction without any branching
// different from a basic block (no single entry point)
// two translation_block may contains the same set of instructions (one of the
// blocks overlaps on the other)
class translation_block
{
public:
    translation_block(uint64_t pc, size_t size, symbol& symbol)
        : pc_(pc), size_(size), symbol_(symbol)
    {
    }

    uint64_t pc() const { return pc_; }
    size_t size() const { return size_; }
    class symbol& symbol() const { return symbol_; }
    const std::vector<instruction*>& instructions() const
    {
        return instructions_;
    }

    void add_instruction(instruction& i) { instructions_.emplace_back(&i); }

private:
    uint64_t pc_ = 0;
    size_t size_ = 0;
    class symbol& symbol_;
    std::vector<instruction*> instructions_;
};

// interface for a plugin (interesting event functions must be overrided)
// instruction and translation_block references remains valid/the same all along
// program execution, thus their addresses can be used as identifiers.
class plugin
{
public:
    plugin(const std::string& name, const std::string& description)
        : name_(name), description_(description)
    {
    }
    virtual ~plugin() {}
    virtual void on_program_start() {}
    virtual void on_block_enter(translation_block&) {}
    virtual void on_instruction_exec(translation_block&, instruction&) {}
    virtual void on_block_exit(translation_block&) {}
    virtual void on_program_end() {}
    const std::string& name() const { return name_; }
    const std::string& description() const { return description_; }
private:
    const std::string name_;
    const std::string description_;
};

// macro to register a plugin from @class_name
#define REGISTER_PLUGIN(class_name)                                            \
    static bool register_##class_name()                                        \
    {                                                                          \
        static class_name plugin;                                              \
        register_plugin(plugin);                                               \
        return true;                                                           \
    }                                                                          \
    static bool register_##class_name##_ = register_##class_name()

// function to register an existing plugin
void register_plugin(plugin& p);

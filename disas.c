/* General "disassemble this chunk" code.  Used for debugging. */
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "disas/bfd.h"
#include "elf.h"

#include "cpu.h"
#include "disas/disas.h"
#include "disas/capstone.h"

typedef struct CPUDebug {
    struct disassemble_info info;
    CPUState *cpu;
} CPUDebug;

/* Filled in by elfload.c.  Simplistic, but will do for now. */
struct syminfo *syminfos = NULL;

/* Retrieve the address of a symbol.  */
uint64_t find_symbol(const char *name, int is_elf_class64)
{
    struct syminfo *syminfo;
    int i;

    for (syminfo = syminfos; syminfo; syminfo = syminfo->next) {
        struct elf64_sym *syms64 = NULL;
        struct elf32_sym *syms32 = NULL;

        if (is_elf_class64) {
            syms64 = syminfo->disas_symtab.elf64;
        }
        else {
            syms32 = syminfo->disas_symtab.elf32;
        }

#define SYMS(i, field) (is_elf_class64            \
                        ? syms64[(i)].st_ ## field     \
                        : syms32[(i)].st_ ## field)

        for (i = 0; i < syminfo->disas_num_syms; i++) {
            if (strcmp(name, syminfo->disas_strtab + SYMS(i, name))) {
                continue;
            }

            return (uint64_t)SYMS(i, value);
        }

#undef SYMS
    }
    return 0;
}

bool find_symbol_bounds(const char *name, bool is_elf_class64, uint64_t *start, uint64_t *size)
{
  struct syminfo *syminfo;
  int i;

  for (syminfo = syminfos; syminfo; syminfo = syminfo->next) {
    struct elf64_sym *syms64 = NULL;
    struct elf32_sym *syms32 = NULL;

    if (is_elf_class64) {
      syms64 = syminfo->disas_symtab.elf64;
    }
    else {
      syms32 = syminfo->disas_symtab.elf32;
    }

#define SYMS(i, field) (is_elf_class64 ? syms64[(i)].st_ ## field  \
                                       : syms32[(i)].st_ ## field)

    for (i = 0; i < syminfo->disas_num_syms; i++) {
      if (strcmp(name, syminfo->disas_strtab + SYMS(i, name))) {
        continue;
      }

      *start = (uint64_t)SYMS(i, value);
      *size  = (uint64_t)SYMS(i, size);
      return true;
    }

#undef SYMS
  }
  return false;
}

target_ulong
translate_pc(target_ulong address_in_file, const char *filename) {
  struct syminfo *syminfo;
  target_ulong ret = address_in_file;
  for (syminfo = syminfos; syminfo; syminfo = syminfo->next) {
    if (!strcmp(syminfo->filename, filename)) {
      return ret + syminfo->load_bias;
    }
  }

  // Not found
  return 0;
}

/* Get LENGTH bytes from info's buffer, at target address memaddr.
   Transfer them to myaddr.  */
int
buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, int length,
                   struct disassemble_info *info)
{
    if (memaddr < info->buffer_vma
        || memaddr + length > info->buffer_vma + info->buffer_length)
        /* Out of bounds.  Use EIO because GDB uses it.  */
        return EIO;
    memcpy (myaddr, info->buffer + (memaddr - info->buffer_vma), length);
    return 0;
}

/* Get LENGTH bytes from info's buffer, at target address memaddr.
   Transfer them to myaddr.  */
static int
target_read_memory (bfd_vma memaddr,
                    bfd_byte *myaddr,
                    int length,
                    struct disassemble_info *info)
{
    CPUDebug *s = container_of(info, CPUDebug, info);

    cpu_memory_rw_debug(s->cpu, memaddr, myaddr, length, 0);
    return 0;
}

/* Print an error message.  We can assume that this is in response to
   an error return from buffer_read_memory.  */
void
perror_memory (int status, bfd_vma memaddr, struct disassemble_info *info)
{
  if (status != EIO)
    /* Can't happen.  */
    (*info->fprintf_func) (info->stream, "Unknown error %d\n", status);
  else
    /* Actually, address between memaddr and memaddr + len was
       out of bounds.  */
    (*info->fprintf_func) (info->stream,
			   "Address 0x%" PRIx64 " is out of bounds.\n", memaddr);
}

/* This could be in a separate file, to save minuscule amounts of space
   in statically linked executables.  */

/* Just print the address is hex.  This is included for completeness even
   though both GDB and objdump provide their own (to print symbolic
   addresses).  */

void
generic_print_address (bfd_vma addr, struct disassemble_info *info)
{
    (*info->fprintf_func) (info->stream, "0x%" PRIx64, addr);
}

/* Print address in hex, truncated to the width of a host virtual address. */
static void
generic_print_host_address(bfd_vma addr, struct disassemble_info *info)
{
    uint64_t mask = ~0ULL >> (64 - (sizeof(void *) * 8));
    generic_print_address(addr & mask, info);
}

/* Just return the given address.  */

int
generic_symbol_at_address (bfd_vma addr, struct disassemble_info *info)
{
  return 1;
}

bfd_vma bfd_getl64 (const bfd_byte *addr)
{
  unsigned long long v;

  v = (unsigned long long) addr[0];
  v |= (unsigned long long) addr[1] << 8;
  v |= (unsigned long long) addr[2] << 16;
  v |= (unsigned long long) addr[3] << 24;
  v |= (unsigned long long) addr[4] << 32;
  v |= (unsigned long long) addr[5] << 40;
  v |= (unsigned long long) addr[6] << 48;
  v |= (unsigned long long) addr[7] << 56;
  return (bfd_vma) v;
}

bfd_vma bfd_getl32 (const bfd_byte *addr)
{
  unsigned long v;

  v = (unsigned long) addr[0];
  v |= (unsigned long) addr[1] << 8;
  v |= (unsigned long) addr[2] << 16;
  v |= (unsigned long) addr[3] << 24;
  return (bfd_vma) v;
}

bfd_vma bfd_getb32 (const bfd_byte *addr)
{
  unsigned long v;

  v = (unsigned long) addr[0] << 24;
  v |= (unsigned long) addr[1] << 16;
  v |= (unsigned long) addr[2] << 8;
  v |= (unsigned long) addr[3];
  return (bfd_vma) v;
}

bfd_vma bfd_getl16 (const bfd_byte *addr)
{
  unsigned long v;

  v = (unsigned long) addr[0];
  v |= (unsigned long) addr[1] << 8;
  return (bfd_vma) v;
}

bfd_vma bfd_getb16 (const bfd_byte *addr)
{
  unsigned long v;

  v = (unsigned long) addr[0] << 24;
  v |= (unsigned long) addr[1] << 16;
  return (bfd_vma) v;
}

static int print_insn_objdump(bfd_vma pc, disassemble_info *info,
                              const char *prefix)
{
    int i, n = info->buffer_length;
    uint8_t *buf = g_malloc(n);

    info->read_memory_func(pc, buf, n, info);

    for (i = 0; i < n; ++i) {
        if (i % 32 == 0) {
            info->fprintf_func(info->stream, "\n%s: ", prefix);
        }
        info->fprintf_func(info->stream, "%02x", buf[i]);
    }

    g_free(buf);
    return n;
}

static int print_insn_od_host(bfd_vma pc, disassemble_info *info)
{
    return print_insn_objdump(pc, info, "OBJD-H");
}

static int print_insn_od_target(bfd_vma pc, disassemble_info *info)
{
    return print_insn_objdump(pc, info, "OBJD-T");
}

#ifdef CONFIG_CAPSTONE
/* Temporary storage for the capstone library.  This will be alloced via
   malloc with a size private to the library; thus there's no reason not
   to share this across calls and across host vs target disassembly.  */
static __thread cs_insn *cap_insn;

/* Initialize the Capstone library.  */
/* ??? It would be nice to cache this.  We would need one handle for the
   host and one for the target.  For most targets we can reset specific
   parameters via cs_option(CS_OPT_MODE, new_mode), but we cannot change
   CS_ARCH_* in this way.  Thus we would need to be able to close and
   re-open the target handle with a different arch for the target in order
   to handle AArch64 vs AArch32 mode switching.  */
static cs_err cap_disas_start(disassemble_info *info, csh *handle)
{
    cs_mode cap_mode = info->cap_mode;
    cs_err err;

    cap_mode += (info->endian == BFD_ENDIAN_BIG ? CS_MODE_BIG_ENDIAN
                 : CS_MODE_LITTLE_ENDIAN);

    err = cs_open(info->cap_arch, cap_mode, handle);
    if (err != CS_ERR_OK) {
        return err;
    }

    /* ??? There probably ought to be a better place to put this.  */
    if (info->cap_arch == CS_ARCH_X86) {
        /* We don't care about errors (if for some reason the library
           is compiled without AT&T syntax); the user will just have
           to deal with the Intel syntax.  */
        cs_option(*handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }

    /* "Disassemble" unknown insns as ".byte W,X,Y,Z".  */
    cs_option(*handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    /* Allocate temp space for cs_disasm_iter.  */
    if (cap_insn == NULL) {
        cap_insn = cs_malloc(*handle);
        if (cap_insn == NULL) {
            cs_close(handle);
            return CS_ERR_MEM;
        }
    }
    return CS_ERR_OK;
}

static void cap_dump_insn_units(disassemble_info *info, cs_insn *insn,
                                int i, int n)
{
    fprintf_function print = info->fprintf_func;
    FILE *stream = info->stream;

    switch (info->cap_insn_unit) {
    case 4:
        if (info->endian == BFD_ENDIAN_BIG) {
            for (; i < n; i += 4) {
                print(stream, " %08x", ldl_be_p(insn->bytes + i));

            }
        } else {
            for (; i < n; i += 4) {
                print(stream, " %08x", ldl_le_p(insn->bytes + i));
            }
        }
        break;

    case 2:
        if (info->endian == BFD_ENDIAN_BIG) {
            for (; i < n; i += 2) {
                print(stream, " %04x", lduw_be_p(insn->bytes + i));
            }
        } else {
            for (; i < n; i += 2) {
                print(stream, " %04x", lduw_le_p(insn->bytes + i));
            }
        }
        break;

    default:
        for (; i < n; i++) {
            print(stream, " %02x", insn->bytes[i]);
        }
        break;
    }
}

static void cap_dump_insn(disassemble_info *info, cs_insn *insn)
{
    fprintf_function print = info->fprintf_func;
    int i, n, split;

    print(info->stream, "0x%08" PRIx64 ": ", insn->address);

    n = insn->size;
    split = info->cap_insn_split;

    /* Dump the first SPLIT bytes of the instruction.  */
    cap_dump_insn_units(info, insn, 0, MIN(n, split));

    /* Add padding up to SPLIT so that mnemonics line up.  */
    if (n < split) {
        int width = (split - n) / info->cap_insn_unit;
        width *= (2 * info->cap_insn_unit + 1);
        print(info->stream, "%*s", width, "");
    }

    /* Print the actual instruction.  */
    print(info->stream, "  %-8s %s\n", insn->mnemonic, insn->op_str);

    /* Dump any remaining part of the insn on subsequent lines.  */
    for (i = split; i < n; i += split) {
        print(info->stream, "0x%08" PRIx64 ": ", insn->address + i);
        cap_dump_insn_units(info, insn, i, MIN(n, i + split));
        print(info->stream, "\n");
    }
}

/* Disassemble SIZE bytes at PC for the target.  */
static bool cap_disas_target(disassemble_info *info, uint64_t pc, size_t size)
{
    uint8_t cap_buf[1024];
    csh handle;
    cs_insn *insn;
    size_t csize = 0;

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }
    insn = cap_insn;

    while (1) {
        size_t tsize = MIN(sizeof(cap_buf) - csize, size);
        const uint8_t *cbuf = cap_buf;

        target_read_memory(pc + csize, cap_buf + csize, tsize, info);
        csize += tsize;
        size -= tsize;

        while (cs_disasm_iter(handle, &cbuf, &csize, &pc, insn)) {
           cap_dump_insn(info, insn);
        }

        /* If the target memory is not consumed, go back for more... */
        if (size != 0) {
            /* ... taking care to move any remaining fractional insn
               to the beginning of the buffer.  */
            if (csize != 0) {
                memmove(cap_buf, cbuf, csize);
            }
            continue;
        }

        /* Since the target memory is consumed, we should not have
           a remaining fractional insn.  */
        if (csize != 0) {
            (*info->fprintf_func)(info->stream,
                "Disassembler disagrees with translator "
                "over instruction decoding\n"
                "Please report this to qemu-devel@nongnu.org\n");
        }
        break;
    }

    cs_close(&handle);
    return true;
}

/* Disassemble SIZE bytes at CODE for the host.  */
static bool cap_disas_host(disassemble_info *info, void *code, size_t size)
{
    csh handle;
    const uint8_t *cbuf;
    cs_insn *insn;
    uint64_t pc;

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }
    insn = cap_insn;

    cbuf = code;
    pc = (uintptr_t)code;

    while (cs_disasm_iter(handle, &cbuf, &size, &pc, insn)) {
       cap_dump_insn(info, insn);
    }
    if (size != 0) {
        (*info->fprintf_func)(info->stream,
            "Disassembler disagrees with TCG over instruction encoding\n"
            "Please report this to qemu-devel@nongnu.org\n");
    }

    cs_close(&handle);
    return true;
}

#if !defined(CONFIG_USER_ONLY)
/* Disassemble COUNT insns at PC for the target.  */
static bool cap_disas_monitor(disassemble_info *info, uint64_t pc, int count)
{
    uint8_t cap_buf[32];
    csh handle;
    cs_insn *insn;
    size_t csize = 0;

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }
    insn = cap_insn;

    while (1) {
        /* We want to read memory for one insn, but generically we do not
           know how much memory that is.  We have a small buffer which is
           known to be sufficient for all supported targets.  Try to not
           read beyond the page, Just In Case.  For even more simplicity,
           ignore the actual target page size and use a 1k boundary.  If
           that turns out to be insufficient, we'll come back around the
           loop and read more.  */
        uint64_t epc = QEMU_ALIGN_UP(pc + csize + 1, 1024);
        size_t tsize = MIN(sizeof(cap_buf) - csize, epc - pc);
        const uint8_t *cbuf = cap_buf;

        /* Make certain that we can make progress.  */
        assert(tsize != 0);
        info->read_memory_func(pc, cap_buf + csize, tsize, info);
        csize += tsize;

        if (cs_disasm_iter(handle, &cbuf, &csize, &pc, insn)) {
            cap_dump_insn(info, insn);
            if (--count <= 0) {
                break;
            }
        }
        memmove(cap_buf, cbuf, csize);
    }

    cs_close(&handle);
    return true;
}
#endif /* !CONFIG_USER_ONLY */
#else
# define cap_disas_target(i, p, s)  false
# define cap_disas_host(i, p, s)  false
# define cap_disas_monitor(i, p, c)  false
#endif /* CONFIG_CAPSTONE */

/* Disassemble this for me please... (debugging).  */
void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    target_ulong pc;
    int count;
    CPUDebug s;

    INIT_DISASSEMBLE_INFO(s.info, out, fprintf);

    s.cpu = cpu;
    s.info.read_memory_func = target_read_memory;
    s.info.buffer_vma = code;
    s.info.buffer_length = size;
    s.info.print_address_func = generic_print_address;
    s.info.cap_arch = -1;
    s.info.cap_mode = 0;
    s.info.cap_insn_unit = 4;
    s.info.cap_insn_split = 4;

#ifdef TARGET_WORDS_BIGENDIAN
    s.info.endian = BFD_ENDIAN_BIG;
#else
    s.info.endian = BFD_ENDIAN_LITTLE;
#endif

    if (cc->disas_set_info) {
        cc->disas_set_info(cpu, &s.info);
    }

    if (s.info.cap_arch >= 0 && cap_disas_target(&s.info, code, size)) {
        return;
    }

    if (s.info.print_insn == NULL) {
        s.info.print_insn = print_insn_od_target;
    }

    for (pc = code; size > 0; pc += count, size -= count) {
	fprintf(out, "0x" TARGET_FMT_lx ":  ", pc);
	count = s.info.print_insn(pc, &s.info);
	fprintf(out, "\n");
	if (count < 0)
	    break;
        if (size < count) {
            fprintf(out,
                    "Disassembler disagrees with translator over instruction "
                    "decoding\n"
                    "Please report this to qemu-devel@nongnu.org\n");
            break;
        }
    }
}

/* Disassemble this for me please... (debugging). */
void disas(FILE *out, void *code, unsigned long size)
{
    uintptr_t pc;
    int count;
    CPUDebug s;
    int (*print_insn)(bfd_vma pc, disassemble_info *info) = NULL;

    INIT_DISASSEMBLE_INFO(s.info, out, fprintf);
    s.info.print_address_func = generic_print_host_address;

    s.info.buffer = code;
    s.info.buffer_vma = (uintptr_t)code;
    s.info.buffer_length = size;
    s.info.cap_arch = -1;
    s.info.cap_mode = 0;
    s.info.cap_insn_unit = 4;
    s.info.cap_insn_split = 4;

#ifdef HOST_WORDS_BIGENDIAN
    s.info.endian = BFD_ENDIAN_BIG;
#else
    s.info.endian = BFD_ENDIAN_LITTLE;
#endif
#if defined(CONFIG_TCG_INTERPRETER)
    print_insn = print_insn_tci;
#elif defined(__i386__)
    s.info.mach = bfd_mach_i386_i386;
    print_insn = print_insn_i386;
    s.info.cap_arch = CS_ARCH_X86;
    s.info.cap_mode = CS_MODE_32;
    s.info.cap_insn_unit = 1;
    s.info.cap_insn_split = 8;
#elif defined(__x86_64__)
    s.info.mach = bfd_mach_x86_64;
    print_insn = print_insn_i386;
    s.info.cap_arch = CS_ARCH_X86;
    s.info.cap_mode = CS_MODE_64;
    s.info.cap_insn_unit = 1;
    s.info.cap_insn_split = 8;
#elif defined(_ARCH_PPC)
    s.info.disassembler_options = (char *)"any";
    print_insn = print_insn_ppc;
    s.info.cap_arch = CS_ARCH_PPC;
# ifdef _ARCH_PPC64
    s.info.cap_mode = CS_MODE_64;
# endif
#elif defined(__riscv__)
    print_insn = print_insn_riscv;
#elif defined(__aarch64__) && defined(CONFIG_ARM_A64_DIS)
    print_insn = print_insn_arm_a64;
    s.info.cap_arch = CS_ARCH_ARM64;
#elif defined(__alpha__)
    print_insn = print_insn_alpha;
#elif defined(__sparc__)
    print_insn = print_insn_sparc;
    s.info.mach = bfd_mach_sparc_v9b;
#elif defined(__arm__)
    print_insn = print_insn_arm;
    s.info.cap_arch = CS_ARCH_ARM;
    /* TCG only generates code for arm mode.  */
#elif defined(__MIPSEB__)
    print_insn = print_insn_big_mips;
#elif defined(__MIPSEL__)
    print_insn = print_insn_little_mips;
#elif defined(__m68k__)
    print_insn = print_insn_m68k;
#elif defined(__s390__)
    print_insn = print_insn_s390;
#elif defined(__hppa__)
    print_insn = print_insn_hppa;
#endif

    if (s.info.cap_arch >= 0 && cap_disas_host(&s.info, code, size)) {
        return;
    }

    if (print_insn == NULL) {
        print_insn = print_insn_od_host;
    }
    for (pc = (uintptr_t)code; size > 0; pc += count, size -= count) {
        fprintf(out, "0x%08" PRIxPTR ":  ", pc);
        count = print_insn(pc, &s.info);
	fprintf(out, "\n");
	if (count < 0)
	    break;
    }
}

/* Look up symbol for debugging purpose.  Returns "" if unknown. */
const char *lookup_symbol(target_ulong orig_addr)
{
    const char *symbol = "";
    struct syminfo *s;

    for (s = syminfos; s; s = s->next) {
        symbol = s->lookup_symbol(s, orig_addr, NULL, NULL);
        if (symbol[0] != '\0') {
            break;
        }
    }

    return symbol;
}

/* Look up symbol/filename for debugging purpose.  */
bool lookup_symbol2(target_ulong orig_addr, const char **symbol, const char **filename)
{
    struct syminfo *s;

    for (s = syminfos; s; s = s->next) {
        *symbol = s->lookup_symbol(s, orig_addr, NULL, NULL);
        if (*symbol[0] != '\0') {
            *filename = s->filename;
            return true;
        }
    }

    *symbol = "";
    *filename = "";
    return false;
}

bool lookup_symbol3(target_ulong orig_addr, const char **symbol, const char **filename, uint64_t *address)
{
    struct syminfo *s;

    for (s = syminfos; s; s = s->next) {
#if defined(CONFIG_USER_ONLY)
        target_ulong target_address;
#else
        hwaddr target_address;
#endif
        *symbol = s->lookup_symbol(s, orig_addr, &target_address, NULL);
        if (*symbol[0] != '\0') {
            *filename = s->filename;
            *address = target_address;
            return true;
        }
    }

    *symbol = "";
    *filename = "";
    *address = orig_addr;
    return false;
}

bool lookup_symbol4(target_ulong orig_addr, const char **symbol, const char **filename, uint64_t *address, uint64_t *size)
{
    struct syminfo *s;

    for (s = syminfos; s; s = s->next) {
#if defined(CONFIG_USER_ONLY)
        target_ulong target_address, target_size;
#else
        hwaddr target_address, target_size;
#endif
        *symbol = s->lookup_symbol(s, orig_addr, &target_address, &target_size);
        if (*symbol[0] != '\0') {
            *filename = s->filename;
            *address = target_address;
            *size = target_size;
            return true;
        }
    }

    *symbol = "";
    *filename = "";
    *address = orig_addr;
    *size = 0;
    return false;
}

bool lookup_symbol5(target_ulong orig_addr, const char **symbol, const char **filename, uint64_t *address, uint64_t *size, uint64_t *load_bias)
{
  struct syminfo *s;

  for (s = syminfos; s; s = s->next) {
#if defined(CONFIG_USER_ONLY)
    target_ulong target_address, target_size;
#else
    hwaddr target_address, target_size;
#endif
    *symbol = s->lookup_symbol(s, orig_addr, &target_address, &target_size);
    if (*symbol[0] != '\0') {
      *filename = s->filename;
      *address = target_address;
      *size = target_size;
      *load_bias = s->load_bias;
      return true;
    }
  }

  *symbol = "";
  *filename = "";
  *address = orig_addr;
  *size = 0;
  *load_bias = 0;
  return false;
}


#if !defined(CONFIG_USER_ONLY)

#include "monitor/monitor.h"

static int
physical_read_memory(bfd_vma memaddr, bfd_byte *myaddr, int length,
                     struct disassemble_info *info)
{
    cpu_physical_memory_read(memaddr, myaddr, length);
    return 0;
}

/* Disassembler for the monitor.  */
void monitor_disas(Monitor *mon, CPUState *cpu,
                   target_ulong pc, int nb_insn, int is_physical)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int count, i;
    CPUDebug s;

    INIT_DISASSEMBLE_INFO(s.info, (FILE *)mon, monitor_fprintf);

    s.cpu = cpu;
    s.info.read_memory_func
        = (is_physical ? physical_read_memory : target_read_memory);
    s.info.print_address_func = generic_print_address;
    s.info.buffer_vma = pc;
    s.info.cap_arch = -1;
    s.info.cap_mode = 0;
    s.info.cap_insn_unit = 4;
    s.info.cap_insn_split = 4;

#ifdef TARGET_WORDS_BIGENDIAN
    s.info.endian = BFD_ENDIAN_BIG;
#else
    s.info.endian = BFD_ENDIAN_LITTLE;
#endif

    if (cc->disas_set_info) {
        cc->disas_set_info(cpu, &s.info);
    }

    if (s.info.cap_arch >= 0 && cap_disas_monitor(&s.info, pc, nb_insn)) {
        return;
    }

    if (!s.info.print_insn) {
        monitor_printf(mon, "0x" TARGET_FMT_lx
                       ": Asm output not supported on this arch\n", pc);
        return;
    }

    for(i = 0; i < nb_insn; i++) {
	monitor_printf(mon, "0x" TARGET_FMT_lx ":  ", pc);
        count = s.info.print_insn(pc, &s.info);
	monitor_printf(mon, "\n");
	if (count < 0)
	    break;
        pc += count;
    }
}
#endif

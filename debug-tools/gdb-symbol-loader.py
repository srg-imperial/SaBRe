import re
import subprocess

# Make a .gdbinit file and add:
# source ~/SaBRe/debug-tools/gdb-symbol-loader.py
# Invoke from GDB as: sbr-sym

# Useful gdb commands: info file, remove-symbol-file


def relocatesections(filename, addr):
    p = subprocess.Popen(["readelf", "-W", "-S", filename], stdout=subprocess.PIPE)

    sections = []
    textaddr = "0"
    for line in p.stdout.readlines():
        line = line.decode("utf-8").strip()
        if not line.startswith("[") or line.startswith("[Nr]"):
            continue

        line = re.sub(r" +", " ", line)
        line = re.sub(r"\[ *(\d+)\]", "\g<1>", line)
        fieldsvalue = line.split(" ")
        fieldsname = [
            "number",
            "name",
            "type",
            "addr",
            "offset",
            "size",
            "entsize",
            "flags",
            "link",
            "info",
            "addralign",
        ]
        sec = dict(zip(fieldsname, fieldsvalue))

        if sec["number"] == "0":
            continue

        sections.append(sec)

        if sec["name"] == ".text":
            textaddr = sec["addr"]

    return (textaddr, sections)


class AddSymbolFileAll(gdb.Command):
    """The right version for add-symbol-file"""

    def __init__(self):
        super(AddSymbolFileAll, self).__init__("add-symbol-file-all", gdb.COMMAND_USER)
        self.dont_repeat()

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        filename = argv[0]

        if len(argv) > 1:
            offset = int(str(gdb.parse_and_eval(argv[1])), 0)
        else:
            offset = 0

        (textaddr, sections) = relocatesections(filename, offset)

        cmd = "add-symbol-file %s 0x%08x" % (filename, int(textaddr, 16) + offset)

        for s in sections:
            addr = int(s["addr"], 16)
            if s["name"] == ".text" or addr == 0:
                continue

            cmd += " -s %s 0x%08x" % (s["name"], addr + offset)

        gdb.execute(cmd)


class RemoveSymbolFileAll(gdb.Command):
    """The right version for remove-symbol-file"""

    def __init__(self):
        super(RemoveSymbolFileAll, self).__init__(
            "remove-symbol-file-all", gdb.COMMAND_USER
        )
        self.dont_repeat()

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        filename = argv[0]

        if len(argv) > 1:
            offset = int(str(gdb.parse_and_eval(argv[1])), 0)
        else:
            offset = 0

        (textaddr, _) = relocatesections(filename, offset)

        cmd = "remove-symbol-file -a 0x%08x" % (int(textaddr, 16) + offset)
        gdb.execute(cmd)


AddSymbolFileAll()
RemoveSymbolFileAll()


class AddSaBReSymbols(gdb.Command):
    def get_offsets(self, path):
        text_offset, bss_offset, rodata_offset = 0, 0, 0
        output = subprocess.check_output(["readelf", "-WS", path])
        for line in output.splitlines():
            line = str(line)
            if "] .text " in line:
                text_offset = "0x" + line.split()[5]
            if "] .bss " in line:
                bss_offset = "0x" + line.split()[5]
            if "] .rodata " in line:
                rodata_offset = "0x" + line.split()[5]
        assert text_offset != 0 and bss_offset != 0
        return text_offset, bss_offset, rodata_offset

    def run_add_symbol_file(
        self, from_tty, lib, addr_start, text_offset, bss_offset, rodata_offset
    ):
        gdb_cmd = (
            f"add-symbol-file {lib}"
            f" -s .text {addr_start}+{text_offset}"
            f" -s .bss {addr_start}+{bss_offset}"
        )
        if rodata_offset:
            gdb_cmd += f" -s .rodata {addr_start}+{rodata_offset}"
        print(gdb_cmd)
        gdb.execute(gdb_cmd, from_tty)

    def run_add_source_files(self, from_tty):
        srcs = [
            "/usr/src/glibc/glibc-2.27/nptl",
            "/usr/src/glibc/glibc-2.27/elf",
            "/usr/src/glibc/glibc-2.27/libio",
            "/usr/src/gcc-7/src/libsanitizer/include/sanitizer",
        ]
        for src in srcs:
            gdb_cmd = f"dir {src}"
            print(gdb_cmd)
            gdb.execute(gdb_cmd, from_tty)

    def __init__(self):
        super(AddSaBReSymbols, self).__init__("sbr-sym", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        print("Load source dirs")
        self.run_add_source_files(from_tty)

        cmd = "info proc mappings"
        maplines = gdb.execute(cmd, from_tty, True).split("\n")

        ignore_libs = ["so.cache"]

        print("Load symbols of mremap-ed libraries")

        mremap_libs = [
            "libpthread",
            "libc",
            "sbr_client.",
            "librt",
            "libresolv",
        ]
        rewritten_libs = set()
        for i, line in enumerate(maplines):
            tokens = line.strip().split()

            # Skip line if:
            # 1) Doesn't have enough info (e.g `process 16240`)
            # 2) It's last line
            # 3) Doesn't have the `0x1000 0x0` marker
            # 4) Next line doesn't have enough info
            # 5) Next line is not a shared object library
            if (
                i + 1 >= len(maplines)
                or len(tokens) != 4
                or tokens[2] != "0x1000"
                or tokens[3] != "0x0"
            ):
                continue

            next_tokens = maplines[i + 1].strip().split()

            if len(next_tokens) != 5 or not next_tokens[4].startswith("/"):
                continue

            # Skip intermidiate lib caches
            if any(True for lib in ignore_libs if lib in next_tokens[4]):
                continue

            if any([True for lib in mremap_libs if lib in next_tokens[4]]):
                addr_start = tokens[0]
                lib = next_tokens[4]
                text_offset, bss_offset, rodata_offset = self.get_offsets(lib)

                self.run_add_symbol_file(
                    from_tty, lib, addr_start, text_offset, bss_offset, rodata_offset
                )

                rewritten_libs.add(lib)

        print("Load symbols of normal libraries")

        parsed_libs = set()
        for i, line in enumerate(maplines):
            # If line doesn't have enough info, skip
            tokens = line.strip().split()
            if (
                len(tokens) != 5
                or not tokens[4].startswith("/")
                or tokens[4] in rewritten_libs
                or tokens[4] in parsed_libs
            ):
                continue

            # Skip intermidiate lib caches
            if any(True for lib in ignore_libs if lib in tokens[4]):
                continue

            addr_start = tokens[0]
            lib = tokens[4]
            text_offset, bss_offset, rodata_offset = self.get_offsets(lib)

            self.run_add_symbol_file(
                from_tty, lib, addr_start, text_offset, bss_offset, rodata_offset
            )

            parsed_libs.add(lib)


AddSaBReSymbols()

/*
 *  PatchELF is a utility to modify properties of ELF executables and libraries
 *  Copyright (C) 2004-2016  Eelco Dolstra <edolstra@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <elf.h>

static bool debugMode = false;

static std::vector<std::string> fileNames;
static std::string outputFileName;
static bool alwaysWrite = false;
#ifdef DEFAULT_PAGESIZE
static int forcedPageSize = DEFAULT_PAGESIZE;
#else
static int forcedPageSize = -1;
#endif

typedef std::shared_ptr<std::vector<unsigned char>> FileContents;

#define ElfFileParams                                                          \
  class Elf_Ehdr, class Elf_Phdr, class Elf_Shdr, class Elf_Addr,              \
      class Elf_Off, class Elf_Dyn, class Elf_Sym, class Elf_Verneed
#define ElfFileParamNames                                                      \
  Elf_Ehdr, Elf_Phdr, Elf_Shdr, Elf_Addr, Elf_Off, Elf_Dyn, Elf_Sym, Elf_Verneed

template <ElfFileParams> class ElfFile {
public:
  const FileContents fileContents;

private:
  unsigned char *contents;

  Elf_Ehdr *hdr;
  std::vector<Elf_Phdr> phdrs;
  std::vector<Elf_Shdr> shdrs;

  bool littleEndian;

  bool changed = false;

  bool isExecutable = false;

  typedef std::string SectionName;
  typedef std::map<SectionName, std::string> ReplacedSections;

  ReplacedSections replacedSections;

  std::string sectionNames; /* content of the .shstrtab section */

  /* Align on 4 or 8 bytes boundaries on 32- or 64-bit platforms
     respectively. */
  size_t sectionAlignment = sizeof(Elf_Off);

  std::vector<SectionName> sectionsByOldIndex;

public:
  ElfFile(FileContents fileContents);

  bool isChanged() { return changed; }

private:
  struct CompPhdr {
    ElfFile *elfFile;
    bool operator()(const Elf_Phdr &x, const Elf_Phdr &y) {
      // A PHDR comes before everything else.
      if (y.p_type == PT_PHDR)
        return false;
      if (x.p_type == PT_PHDR)
        return true;

      // Sort non-PHDRs by address.
      return elfFile->rdi(x.p_paddr) < elfFile->rdi(y.p_paddr);
    }
  };

  friend struct CompPhdr;

  void sortPhdrs();

  struct CompShdr {
    ElfFile *elfFile;
    bool operator()(const Elf_Shdr &x, const Elf_Shdr &y) {
      return elfFile->rdi(x.sh_offset) < elfFile->rdi(y.sh_offset);
    }
  };

  friend struct CompShdr;

  unsigned int getPageSize() const;

  void sortShdrs();

  void shiftFile(unsigned int extraPages, Elf_Addr startPage);

  std::string getSectionName(const Elf_Shdr &shdr) const;

  Elf_Shdr &findSection(const SectionName &sectionName);

  Elf_Shdr *findSection2(const SectionName &sectionName);

  unsigned int findSection3(const SectionName &sectionName);

  std::string &replaceSection(const SectionName &sectionName,
                              unsigned int size);

  bool haveReplacedSection(const SectionName &sectionName) const;

  void writeReplacedSections(Elf_Off &curOff, Elf_Addr startAddr,
                             Elf_Off startOffset);

  void rewriteHeaders(Elf_Addr phdrAddress);

  void rewriteSectionsLibrary();

  void rewriteSectionsExecutable();

public:
  void rewriteSections();

  void addNeeded(const std::set<std::string> &libs);

private:
  /* Convert an integer in big or little endian representation (as
     specified by the ELF header) to this platform's integer
     representation. */
  template <class I> I rdi(I i) const;

  /* Convert back to the ELF representation. */
  template <class I> I wri(I &t, unsigned long long i) const {
    t = rdi((I)i);
    return i;
  }
};

/* !!! G++ creates broken code if this function is inlined, don't know
   why... */
template <ElfFileParams>
template <class I>
I ElfFile<ElfFileParamNames>::rdi(I i) const {
  I r = 0;
  if (littleEndian) {
    for (unsigned int n = 0; n < sizeof(I); ++n) {
      r |= ((I) * (((unsigned char *)&i) + n)) << (n * 8);
    }
  } else {
    for (unsigned int n = 0; n < sizeof(I); ++n) {
      r |= ((I) * (((unsigned char *)&i) + n)) << ((sizeof(I) - n - 1) * 8);
    }
  }
  return r;
}

/* Ugly: used to erase DT_RUNPATH when using --force-rpath. */
#define DT_IGNORE 0x00726e67

static void debug(const char *format, ...) {
  if (debugMode) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
  }
}

void fmt2(std::ostringstream &out) {}

template <typename T, typename... Args>
void fmt2(std::ostringstream &out, T x, Args... args) {
  out << x;
  fmt2(out, args...);
}

template <typename... Args> std::string fmt(Args... args) {
  std::ostringstream out;
  fmt2(out, args...);
  return out.str();
}

struct SysError : std::runtime_error {
  int errNo;
  SysError(const std::string &msg)
      : std::runtime_error(fmt(msg + ": " + strerror(errno))), errNo(errno) {}
};

__attribute__((noreturn)) static void error(std::string msg) {
  if (errno)
    throw SysError(msg);
  else
    throw std::runtime_error(msg);
}

static void growFile(FileContents contents, size_t newSize) {
  if (newSize > contents->capacity())
    error("maximum file size exceeded");
  if (newSize <= contents->size())
    return;
  contents->resize(newSize, 0);
}

static FileContents
readFile(std::string fileName,
         size_t cutOff = std::numeric_limits<size_t>::max()) {
  struct stat st;
  if (stat(fileName.c_str(), &st) != 0)
    throw SysError(fmt("getting info about '", fileName, "'"));

  if ((uint64_t)st.st_size > (uint64_t)std::numeric_limits<size_t>::max())
    throw SysError(
        fmt("cannot read file of size ", st.st_size, " into memory"));

  size_t size = std::min(cutOff, (size_t)st.st_size);

  FileContents contents = std::make_shared<std::vector<unsigned char>>();
  contents->reserve(size + 32 * 1024 * 1024);
  contents->resize(size, 0);

  int fd = open(fileName.c_str(), O_RDONLY);
  if (fd == -1)
    throw SysError(fmt("opening '", fileName, "'"));

  size_t bytesRead = 0;
  ssize_t portion;
  while ((portion = read(fd, contents->data() + bytesRead, size - bytesRead)) >
         0)
    bytesRead += portion;

  if (bytesRead != size)
    throw SysError(fmt("reading '", fileName, "'"));

  close(fd);

  return contents;
}

struct ElfType {
  bool is32Bit;
  int machine; // one of EM_*
};

ElfType getElfType(const FileContents &fileContents) {
  /* Check the ELF header for basic validity. */
  if (fileContents->size() < (off_t)sizeof(Elf32_Ehdr))
    error("missing ELF header");

  auto contents = fileContents->data();

  if (memcmp(contents, ELFMAG, SELFMAG) != 0)
    error("not an ELF executable");

  if (contents[EI_VERSION] != EV_CURRENT)
    error("unsupported ELF version");

  if (contents[EI_CLASS] != ELFCLASS32 && contents[EI_CLASS] != ELFCLASS64)
    error("ELF executable is not 32 or 64 bit");

  bool is32Bit = contents[EI_CLASS] == ELFCLASS32;

  // FIXME: endianness
  return ElfType{is32Bit, is32Bit ? ((Elf32_Ehdr *)contents)->e_machine
                                  : ((Elf64_Ehdr *)contents)->e_machine};
}

static void checkPointer(const FileContents &contents, void *p,
                         unsigned int size) {
  unsigned char *q = (unsigned char *)p;
  assert(q >= contents->data() &&
         q + size <= contents->data() + contents->size());
}

template <ElfFileParams>
ElfFile<ElfFileParamNames>::ElfFile(FileContents fileContents)
    : fileContents(fileContents), contents(fileContents->data()) {
  /* Check the ELF header for basic validity. */
  if (fileContents->size() < (off_t)sizeof(Elf_Ehdr))
    error("missing ELF header");

  hdr = (Elf_Ehdr *)fileContents->data();

  if (memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0)
    error("not an ELF executable");

  littleEndian = hdr->e_ident[EI_DATA] == ELFDATA2LSB;

  if (rdi(hdr->e_type) != ET_EXEC && rdi(hdr->e_type) != ET_DYN)
    error("wrong ELF type");

  if ((size_t)(rdi(hdr->e_phoff) + rdi(hdr->e_phnum) * rdi(hdr->e_phentsize)) >
      fileContents->size())
    error("program header table out of bounds");

  if (rdi(hdr->e_shnum) == 0)
    error("no section headers. The input file is probably a statically linked, "
          "self-decompressing binary");

  if ((size_t)(rdi(hdr->e_shoff) + rdi(hdr->e_shnum) * rdi(hdr->e_shentsize)) >
      fileContents->size())
    error("section header table out of bounds");

  if (rdi(hdr->e_phentsize) != sizeof(Elf_Phdr))
    error("program headers have wrong size");

  /* Copy the program and section headers. */
  for (int i = 0; i < rdi(hdr->e_phnum); ++i) {
    phdrs.push_back(*((Elf_Phdr *)(contents + rdi(hdr->e_phoff)) + i));
    if (rdi(phdrs[i].p_type) == PT_INTERP)
      isExecutable = true;
  }

  for (int i = 0; i < rdi(hdr->e_shnum); ++i)
    shdrs.push_back(*((Elf_Shdr *)(contents + rdi(hdr->e_shoff)) + i));

  /* Get the section header string table section (".shstrtab").  Its
     index in the section header table is given by e_shstrndx field
     of the ELF header. */
  unsigned int shstrtabIndex = rdi(hdr->e_shstrndx);
  assert(shstrtabIndex < shdrs.size());
  unsigned int shstrtabSize = rdi(shdrs[shstrtabIndex].sh_size);
  char *shstrtab = (char *)contents + rdi(shdrs[shstrtabIndex].sh_offset);
  checkPointer(fileContents, shstrtab, shstrtabSize);

  assert(shstrtabSize > 0);
  assert(shstrtab[shstrtabSize - 1] == 0);

  sectionNames = std::string(shstrtab, shstrtabSize);

  sectionsByOldIndex.resize(hdr->e_shnum);
  for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
    sectionsByOldIndex[i] = getSectionName(shdrs[i]);
}

template <ElfFileParams>
unsigned int ElfFile<ElfFileParamNames>::getPageSize() const {
  if (forcedPageSize > 0)
    return forcedPageSize;

  // Architectures (and ABIs) can have different minimum section alignment
  // requirements. There is no authoritative list of these values. The
  // current list is extracted from GNU gold's source code (abi_pagesize).
  switch (hdr->e_machine) {
  case EM_SPARC:
  case EM_MIPS:
  case EM_PPC:
  case EM_PPC64:
  case EM_AARCH64:
  case EM_TILEGX:
    return 0x10000;
  default:
    return 0x1000;
  }
}

template <ElfFileParams> void ElfFile<ElfFileParamNames>::sortPhdrs() {
  /* Sort the segments by offset. */
  CompPhdr comp;
  comp.elfFile = this;
  sort(phdrs.begin(), phdrs.end(), comp);
}

template <ElfFileParams> void ElfFile<ElfFileParamNames>::sortShdrs() {
  /* Translate sh_link mappings to section names, since sorting the
     sections will invalidate the sh_link fields. */
  std::map<SectionName, SectionName> linkage;
  for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
    if (rdi(shdrs[i].sh_link) != 0)
      linkage[getSectionName(shdrs[i])] =
          getSectionName(shdrs[rdi(shdrs[i].sh_link)]);

  /* Idem for sh_info on certain sections. */
  std::map<SectionName, SectionName> info;
  for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
    if (rdi(shdrs[i].sh_info) != 0 &&
        (rdi(shdrs[i].sh_type) == SHT_REL || rdi(shdrs[i].sh_type) == SHT_RELA))
      info[getSectionName(shdrs[i])] =
          getSectionName(shdrs[rdi(shdrs[i].sh_info)]);

  /* Idem for the index of the .shstrtab section in the ELF header. */
  SectionName shstrtabName = getSectionName(shdrs[rdi(hdr->e_shstrndx)]);

  /* Sort the sections by offset. */
  CompShdr comp;
  comp.elfFile = this;
  sort(shdrs.begin() + 1, shdrs.end(), comp);

  /* Restore the sh_link mappings. */
  for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
    if (rdi(shdrs[i].sh_link) != 0)
      wri(shdrs[i].sh_link, findSection3(linkage[getSectionName(shdrs[i])]));

  /* And the st_info mappings. */
  for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
    if (rdi(shdrs[i].sh_info) != 0 &&
        (rdi(shdrs[i].sh_type) == SHT_REL || rdi(shdrs[i].sh_type) == SHT_RELA))
      wri(shdrs[i].sh_info, findSection3(info[getSectionName(shdrs[i])]));

  /* And the .shstrtab index. */
  wri(hdr->e_shstrndx, findSection3(shstrtabName));
}

static void writeFile(std::string fileName, FileContents contents) {
  debug("writing %s\n", fileName.c_str());

  int fd = open(fileName.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0777);
  if (fd == -1)
    error("open");

  size_t bytesWritten = 0;
  ssize_t portion;
  while ((portion = write(fd, contents->data() + bytesWritten,
                          contents->size() - bytesWritten)) > 0)
    bytesWritten += portion;

  if (bytesWritten != contents->size())
    error("write");

  if (close(fd) != 0)
    error("close");
}

static unsigned int roundUp(unsigned int n, unsigned int m) {
  return ((n - 1) / m + 1) * m;
}

template <ElfFileParams>
void ElfFile<ElfFileParamNames>::shiftFile(unsigned int extraPages,
                                           Elf_Addr startPage) {
  /* Move the entire contents of the file 'extraPages' pages
     further. */
  unsigned int oldSize = fileContents->size();
  unsigned int shift = extraPages * getPageSize();
  growFile(fileContents, fileContents->size() + extraPages * getPageSize());
  memmove(contents + extraPages * getPageSize(), contents, oldSize);
  memset(contents + sizeof(Elf_Ehdr), 0, shift - sizeof(Elf_Ehdr));

  /* Adjust the ELF header. */
  wri(hdr->e_phoff, sizeof(Elf_Ehdr));
  wri(hdr->e_shoff, rdi(hdr->e_shoff) + shift);

  /* Update the offsets in the section headers. */
  for (int i = 1; i < rdi(hdr->e_shnum); ++i)
    wri(shdrs[i].sh_offset, rdi(shdrs[i].sh_offset) + shift);

  /* Update the offsets in the program headers. */
  for (int i = 0; i < rdi(hdr->e_phnum); ++i) {
    wri(phdrs[i].p_offset, rdi(phdrs[i].p_offset) + shift);
    if (rdi(phdrs[i].p_align) != 0 &&
        (rdi(phdrs[i].p_vaddr) - rdi(phdrs[i].p_offset)) %
                rdi(phdrs[i].p_align) !=
            0) {
      debug("changing alignment of program header %d from %d to %d\n", i,
            rdi(phdrs[i].p_align), getPageSize());
      wri(phdrs[i].p_align, getPageSize());
    }
  }

  /* Add a segment that maps the new program/section headers and
     PT_INTERP segment into memory.  Otherwise glibc will choke. */
  phdrs.resize(rdi(hdr->e_phnum) + 1);
  wri(hdr->e_phnum, rdi(hdr->e_phnum) + 1);
  Elf_Phdr &phdr = phdrs[rdi(hdr->e_phnum) - 1];
  wri(phdr.p_type, PT_LOAD);
  wri(phdr.p_offset, 0);
  wri(phdr.p_vaddr, wri(phdr.p_paddr, startPage));
  wri(phdr.p_filesz, wri(phdr.p_memsz, shift));
  wri(phdr.p_flags, PF_R | PF_W);
  wri(phdr.p_align, getPageSize());
}

template <ElfFileParams>
std::string
ElfFile<ElfFileParamNames>::getSectionName(const Elf_Shdr &shdr) const {
  return std::string(sectionNames.c_str() + rdi(shdr.sh_name));
}

template <ElfFileParams>
Elf_Shdr &
ElfFile<ElfFileParamNames>::findSection(const SectionName &sectionName) {
  auto shdr = findSection2(sectionName);
  if (!shdr) {
    std::string extraMsg = "";
    if (sectionName == ".interp" || sectionName == ".dynamic" ||
        sectionName == ".dynstr")
      extraMsg = ". The input file is most likely statically linked";
    error("cannot find section '" + sectionName + "'" + extraMsg);
  }
  return *shdr;
}

template <ElfFileParams>
Elf_Shdr *
ElfFile<ElfFileParamNames>::findSection2(const SectionName &sectionName) {
  auto i = findSection3(sectionName);
  return i ? &shdrs[i] : 0;
}

template <ElfFileParams>
unsigned int
ElfFile<ElfFileParamNames>::findSection3(const SectionName &sectionName) {
  for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
    if (getSectionName(shdrs[i]) == sectionName)
      return i;
  return 0;
}

template <ElfFileParams>
bool ElfFile<ElfFileParamNames>::haveReplacedSection(
    const SectionName &sectionName) const {
  return (replacedSections.find(sectionName) != replacedSections.end());
}

template <ElfFileParams>
std::string &
ElfFile<ElfFileParamNames>::replaceSection(const SectionName &sectionName,
                                           unsigned int size) {
  ReplacedSections::iterator i = replacedSections.find(sectionName);
  std::string s;

  if (i != replacedSections.end()) {
    s = std::string(i->second);
  } else {
    auto shdr = findSection(sectionName);
    s = std::string((char *)contents + rdi(shdr.sh_offset), rdi(shdr.sh_size));
  }

  s.resize(size);
  replacedSections[sectionName] = s;

  return replacedSections[sectionName];
}

template <ElfFileParams>
void ElfFile<ElfFileParamNames>::writeReplacedSections(Elf_Off &curOff,
                                                       Elf_Addr startAddr,
                                                       Elf_Off startOffset) {
  /* Overwrite the old section contents with 'X's.  Do this
     *before* writing the new section contents (below) to prevent
     clobbering previously written new section contents. */
  for (auto &i : replacedSections) {
    std::string sectionName = i.first;
    Elf_Shdr &shdr = findSection(sectionName);
    if (shdr.sh_type != SHT_NOBITS)
      memset(contents + rdi(shdr.sh_offset), 'X', rdi(shdr.sh_size));
  }

  for (auto &i : replacedSections) {
    std::string sectionName = i.first;
    auto &shdr = findSection(sectionName);
    debug("rewriting section '%s' from offset 0x%x (size %d) to offset 0x%x "
          "(size %d)\n",
          sectionName.c_str(), rdi(shdr.sh_offset), rdi(shdr.sh_size), curOff,
          i.second.size());

    memcpy(contents + curOff, (unsigned char *)i.second.c_str(),
           i.second.size());

    /* Update the section header for this section. */
    wri(shdr.sh_offset, curOff);
    wri(shdr.sh_addr, startAddr + (curOff - startOffset));
    wri(shdr.sh_size, i.second.size());
    wri(shdr.sh_addralign, sectionAlignment);

    /* If this is the .interp section, then the PT_INTERP segment
       must be sync'ed with it. */
    if (sectionName == ".interp") {
      for (unsigned int j = 0; j < phdrs.size(); ++j)
        if (rdi(phdrs[j].p_type) == PT_INTERP) {
          phdrs[j].p_offset = shdr.sh_offset;
          phdrs[j].p_vaddr = phdrs[j].p_paddr = shdr.sh_addr;
          phdrs[j].p_filesz = phdrs[j].p_memsz = shdr.sh_size;
        }
    }

    /* If this is the .dynamic section, then the PT_DYNAMIC segment
       must be sync'ed with it. */
    if (sectionName == ".dynamic") {
      for (unsigned int j = 0; j < phdrs.size(); ++j)
        if (rdi(phdrs[j].p_type) == PT_DYNAMIC) {
          phdrs[j].p_offset = shdr.sh_offset;
          phdrs[j].p_vaddr = phdrs[j].p_paddr = shdr.sh_addr;
          phdrs[j].p_filesz = phdrs[j].p_memsz = shdr.sh_size;
        }
    }

    curOff += roundUp(i.second.size(), sectionAlignment);
  }

  replacedSections.clear();
}

template <ElfFileParams>
void ElfFile<ElfFileParamNames>::rewriteSectionsLibrary() {
  /* For dynamic libraries, we just place the replacement sections
     at the end of the file.  They're mapped into memory by a
     PT_LOAD segment located directly after the last virtual address
     page of other segments. */
  Elf_Addr startPage = 0;
  for (unsigned int i = 0; i < phdrs.size(); ++i) {
    Elf_Addr thisPage =
        roundUp(rdi(phdrs[i].p_vaddr) + rdi(phdrs[i].p_memsz), getPageSize());
    if (thisPage > startPage)
      startPage = thisPage;
  }

  debug("last page is 0x%llx\n", (unsigned long long)startPage);

  /* Because we're adding a new section header, we're necessarily increasing
     the size of the program header table.  This can cause the first section
     to overlap the program header table in memory; we need to shift the first
     few segments to someplace else. */
  /* Some sections may already be replaced so account for that */
  unsigned int i = 1;
  Elf_Addr pht_size = sizeof(Elf_Ehdr) + (phdrs.size() + 1) * sizeof(Elf_Phdr);
  while (shdrs[i].sh_addr <= pht_size && i < rdi(hdr->e_shnum)) {
    if (not haveReplacedSection(getSectionName(shdrs[i])))
      replaceSection(getSectionName(shdrs[i]), shdrs[i].sh_size);
    i++;
  }

  /* Compute the total space needed for the replaced sections */
  off_t neededSpace = 0;
  for (auto &i : replacedSections)
    neededSpace += roundUp(i.second.size(), sectionAlignment);
  debug("needed space is %d\n", neededSpace);

  size_t startOffset = roundUp(fileContents->size(), getPageSize());

  growFile(fileContents, startOffset + neededSpace);

  /* Even though this file is of type ET_DYN, it could actually be
     an executable.  For instance, Gold produces executables marked
     ET_DYN as does LD when linking with pie. If we move PT_PHDR, it
     has to stay in the first PT_LOAD segment or any subsequent ones
     if they're continuous in memory due to linux kernel constraints
     (see BUGS). Since the end of the file would be after bss, we can't
     move PHDR there, we therefore choose to leave PT_PHDR where it is but
     move enough following sections such that we can add the extra PT_LOAD
     section to it. This PT_LOAD segment ensures the sections at the end of
     the file are mapped into memory for ld.so to process.
     We can't use the approach in rewriteSectionsExecutable()
     since DYN executables tend to start at virtual address 0, so
     rewriteSectionsExecutable() won't work because it doesn't have
     any virtual address space to grow downwards into. */
  if (isExecutable && startOffset > startPage) {
    debug("shifting new PT_LOAD segment by %d bytes to work around a Linux "
          "kernel bug\n",
          startOffset - startPage);
    startPage = startOffset;
  }

  /* Add a segment that maps the replaced sections into memory. */
  wri(hdr->e_phoff, sizeof(Elf_Ehdr));
  phdrs.resize(rdi(hdr->e_phnum) + 1);
  wri(hdr->e_phnum, rdi(hdr->e_phnum) + 1);
  Elf_Phdr &phdr = phdrs[rdi(hdr->e_phnum) - 1];
  wri(phdr.p_type, PT_LOAD);
  wri(phdr.p_offset, startOffset);
  wri(phdr.p_vaddr, wri(phdr.p_paddr, startPage));
  wri(phdr.p_filesz, wri(phdr.p_memsz, neededSpace));
  wri(phdr.p_flags, PF_R | PF_W);
  wri(phdr.p_align, getPageSize());

  /* Write out the replaced sections. */
  Elf_Off curOff = startOffset;
  writeReplacedSections(curOff, startPage, startOffset);
  assert(curOff == startOffset + neededSpace);

  /* Write out the updated program and section headers */
  rewriteHeaders(hdr->e_phoff);
}

template <ElfFileParams>
void ElfFile<ElfFileParamNames>::rewriteSectionsExecutable() {
  /* Sort the sections by offset, otherwise we won't correctly find
     all the sections before the last replaced section. */
  sortShdrs();

  /* What is the index of the last replaced section? */
  unsigned int lastReplaced = 0;
  for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i) {
    std::string sectionName = getSectionName(shdrs[i]);
    if (replacedSections.find(sectionName) != replacedSections.end()) {
      debug("using replaced section '%s'\n", sectionName.c_str());
      lastReplaced = i;
    }
  }

  assert(lastReplaced != 0);

  debug("last replaced is %d\n", lastReplaced);

  /* Try to replace all sections before that, as far as possible.
     Stop when we reach an irreplacable section (such as one of type
     SHT_PROGBITS).  These cannot be moved in virtual address space
     since that would invalidate absolute references to them. */
  assert(lastReplaced + 1 < shdrs.size()); /* !!! I'm lazy. */
  size_t startOffset = rdi(shdrs[lastReplaced + 1].sh_offset);
  Elf_Addr startAddr = rdi(shdrs[lastReplaced + 1].sh_addr);
  std::string prevSection;
  for (unsigned int i = 1; i <= lastReplaced; ++i) {
    Elf_Shdr &shdr(shdrs[i]);
    std::string sectionName = getSectionName(shdr);
    debug("looking at section '%s'\n", sectionName.c_str());
    /* !!! Why do we stop after a .dynstr section? I can't
       remember! */
    if ((rdi(shdr.sh_type) == SHT_PROGBITS && sectionName != ".interp") ||
        prevSection == ".dynstr") {
      startOffset = rdi(shdr.sh_offset);
      startAddr = rdi(shdr.sh_addr);
      lastReplaced = i - 1;
      break;
    } else {
      if (replacedSections.find(sectionName) == replacedSections.end()) {
        debug("replacing section '%s' which is in the way\n",
              sectionName.c_str());
        replaceSection(sectionName, rdi(shdr.sh_size));
      }
    }
    prevSection = sectionName;
  }

  debug("first reserved offset/addr is 0x%x/0x%llx\n", startOffset,
        (unsigned long long)startAddr);

  assert(startAddr % getPageSize() == startOffset % getPageSize());
  Elf_Addr firstPage = startAddr - startOffset;
  debug("first page is 0x%llx\n", (unsigned long long)firstPage);

  if (rdi(hdr->e_shoff) < startOffset) {
    /* The section headers occur too early in the file and would be
       overwritten by the replaced sections. Move them to the end of the file
       before proceeding. */
    off_t shoffNew = fileContents->size();
    off_t shSize =
        rdi(hdr->e_shoff) + rdi(hdr->e_shnum) * rdi(hdr->e_shentsize);
    growFile(fileContents, fileContents->size() + shSize);
    wri(hdr->e_shoff, shoffNew);

    /* Rewrite the section header table.  For neatness, keep the
       sections sorted. */
    assert(rdi(hdr->e_shnum) == shdrs.size());
    sortShdrs();
    for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
      *((Elf_Shdr *)(contents + rdi(hdr->e_shoff)) + i) = shdrs[i];
  }

  /* Compute the total space needed for the replaced sections, the
     ELF header, and the program headers. */
  size_t neededSpace = sizeof(Elf_Ehdr) + phdrs.size() * sizeof(Elf_Phdr);
  for (auto &i : replacedSections)
    neededSpace += roundUp(i.second.size(), sectionAlignment);

  debug("needed space is %d\n", neededSpace);

  /* If we need more space at the start of the file, then grow the
     file by the minimum number of pages and adjust internal
     offsets. */
  if (neededSpace > startOffset) {

    /* We also need an additional program header, so adjust for that. */
    neededSpace += sizeof(Elf_Phdr);
    debug("needed space is %d\n", neededSpace);

    unsigned int neededPages =
        roundUp(neededSpace - startOffset, getPageSize()) / getPageSize();
    debug("needed pages is %d\n", neededPages);
    if (neededPages * getPageSize() > firstPage)
      error("virtual address space underrun!");

    firstPage -= neededPages * getPageSize();
    startOffset += neededPages * getPageSize();

    shiftFile(neededPages, firstPage);
  }

  /* Clear out the free space. */
  Elf_Off curOff = sizeof(Elf_Ehdr) + phdrs.size() * sizeof(Elf_Phdr);
  debug("clearing first %d bytes\n", startOffset - curOff);
  memset(contents + curOff, 0, startOffset - curOff);

  /* Write out the replaced sections. */
  writeReplacedSections(curOff, firstPage, 0);
  assert(curOff == neededSpace);

  rewriteHeaders(firstPage + rdi(hdr->e_phoff));
}

template <ElfFileParams> void ElfFile<ElfFileParamNames>::rewriteSections() {
  if (replacedSections.empty())
    return;

  for (auto &i : replacedSections)
    debug("replacing section '%s' with size %d\n", i.first.c_str(),
          i.second.size());

  if (rdi(hdr->e_type) == ET_DYN) {
    debug("this is a dynamic library\n");
    rewriteSectionsLibrary();
  } else if (rdi(hdr->e_type) == ET_EXEC) {
    debug("this is an executable\n");
    rewriteSectionsExecutable();
  } else
    error("unknown ELF type");
}

template <ElfFileParams>
void ElfFile<ElfFileParamNames>::rewriteHeaders(Elf_Addr phdrAddress) {
  /* Rewrite the program header table. */

  /* If there is a segment for the program header table, update it.
     (According to the ELF spec, there can only be one.) */
  for (unsigned int i = 0; i < phdrs.size(); ++i) {
    if (rdi(phdrs[i].p_type) == PT_PHDR) {
      phdrs[i].p_offset = hdr->e_phoff;
      wri(phdrs[i].p_vaddr, wri(phdrs[i].p_paddr, phdrAddress));
      wri(phdrs[i].p_filesz,
          wri(phdrs[i].p_memsz, phdrs.size() * sizeof(Elf_Phdr)));
      break;
    }
  }

  sortPhdrs();

  for (unsigned int i = 0; i < phdrs.size(); ++i)
    *((Elf_Phdr *)(contents + rdi(hdr->e_phoff)) + i) = phdrs[i];

  /* Rewrite the section header table.  For neatness, keep the
     sections sorted. */
  assert(rdi(hdr->e_shnum) == shdrs.size());
  sortShdrs();
  for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i)
    *((Elf_Shdr *)(contents + rdi(hdr->e_shoff)) + i) = shdrs[i];

  /* Update all those nasty virtual addresses in the .dynamic
     section.  Note that not all executables have .dynamic sections
     (e.g., those produced by klibc's klcc). */
  auto shdrDynamic = findSection2(".dynamic");
  if (shdrDynamic) {
    Elf_Dyn *dyn = (Elf_Dyn *)(contents + rdi(shdrDynamic->sh_offset));
    unsigned int d_tag;
    for (; (d_tag = rdi(dyn->d_tag)) != DT_NULL; dyn++)
      if (d_tag == DT_STRTAB)
        dyn->d_un.d_ptr = findSection(".dynstr").sh_addr;
      else if (d_tag == DT_STRSZ)
        dyn->d_un.d_val = findSection(".dynstr").sh_size;
      else if (d_tag == DT_SYMTAB)
        dyn->d_un.d_ptr = findSection(".dynsym").sh_addr;
      else if (d_tag == DT_HASH)
        dyn->d_un.d_ptr = findSection(".hash").sh_addr;
      else if (d_tag == DT_GNU_HASH)
        dyn->d_un.d_ptr = findSection(".gnu.hash").sh_addr;
      else if (d_tag == DT_JMPREL) {
        auto shdr = findSection2(".rel.plt");
        if (!shdr)
          shdr = findSection2(".rela.plt"); /* 64-bit Linux, x86-64 */
        if (!shdr)
          shdr = findSection2(".rela.IA_64.pltoff"); /* 64-bit Linux, IA-64 */
        if (!shdr)
          error("cannot find section corresponding to DT_JMPREL");
        dyn->d_un.d_ptr = shdr->sh_addr;
      } else if (d_tag == DT_REL) { /* !!! hack! */
        auto shdr = findSection2(".rel.dyn");
        /* no idea if this makes sense, but it was needed for some
           program */
        if (!shdr)
          shdr = findSection2(".rel.got");
        /* some programs have neither section, but this doesn't seem
           to be a problem */
        if (!shdr)
          continue;
        dyn->d_un.d_ptr = shdr->sh_addr;
      } else if (d_tag == DT_RELA) {
        auto shdr = findSection2(".rela.dyn");
        /* some programs lack this section, but it doesn't seem to
           be a problem */
        if (!shdr)
          continue;
        dyn->d_un.d_ptr = shdr->sh_addr;
      } else if (d_tag == DT_VERNEED)
        dyn->d_un.d_ptr = findSection(".gnu.version_r").sh_addr;
      else if (d_tag == DT_VERSYM)
        dyn->d_un.d_ptr = findSection(".gnu.version").sh_addr;
  }

  /* Rewrite the .dynsym section.  It contains the indices of the
     sections in which symbols appear, so these need to be
     remapped. */
  for (unsigned int i = 1; i < rdi(hdr->e_shnum); ++i) {
    if (rdi(shdrs[i].sh_type) != SHT_SYMTAB &&
        rdi(shdrs[i].sh_type) != SHT_DYNSYM)
      continue;
    debug("rewriting symbol table section %d\n", i);
    for (size_t entry = 0;
         (entry + 1) * sizeof(Elf_Sym) <= rdi(shdrs[i].sh_size); entry++) {
      Elf_Sym *sym = (Elf_Sym *)(contents + rdi(shdrs[i].sh_offset) +
                                 entry * sizeof(Elf_Sym));
      unsigned int shndx = rdi(sym->st_shndx);
      if (shndx != SHN_UNDEF && shndx < SHN_LORESERVE) {
        if (shndx >= sectionsByOldIndex.size()) {
          fprintf(stderr,
                  "warning: entry %d in symbol table refers to a non-existent "
                  "section, skipping\n",
                  shndx);
          continue;
        }
        std::string section = sectionsByOldIndex.at(shndx);
        assert(!section.empty());
        auto newIndex = findSection3(section); // inefficient
        // debug("rewriting symbol %d: index = %d (%s) -> %d\n", entry, shndx,
        // section.c_str(), newIndex);
        wri(sym->st_shndx, newIndex);
        /* Rewrite st_value.  FIXME: we should do this for all
           types, but most don't actually change. */
        if (ELF32_ST_TYPE(rdi(sym->st_info)) == STT_SECTION)
          wri(sym->st_value, rdi(shdrs[newIndex].sh_addr));
      }
    }
  }
}

static void setSubstr(std::string &s, unsigned int pos, const std::string &t) {
  assert(pos + t.size() <= s.size());
  copy(t.begin(), t.end(), s.begin() + pos);
}

template <ElfFileParams>
void ElfFile<ElfFileParamNames>::addNeeded(const std::set<std::string> &libs) {
  if (libs.empty())
    return;

  auto shdrDynamic = findSection(".dynamic");
  auto shdrDynStr = findSection(".dynstr");

  /* add all new libs to the dynstr string table */
  unsigned int length = 0;
  for (auto &i : libs)
    length += i.size() + 1;

  std::string &newDynStr =
      replaceSection(".dynstr", rdi(shdrDynStr.sh_size) + length + 1);
  std::set<Elf64_Xword> libStrings;
  unsigned int pos = 0;
  for (auto &i : libs) {
    setSubstr(newDynStr, rdi(shdrDynStr.sh_size) + pos, i + '\0');
    libStrings.insert(rdi(shdrDynStr.sh_size) + pos);
    pos += i.size() + 1;
  }

  /* add all new needed entries to the dynamic section */
  std::string &newDynamic = replaceSection(
      ".dynamic", rdi(shdrDynamic.sh_size) + sizeof(Elf_Dyn) * libs.size());

  unsigned int idx = 0;
  for (; rdi(((Elf_Dyn *)newDynamic.c_str())[idx].d_tag) != DT_NULL; idx++)
    ;
  debug("DT_NULL index is %d\n", idx);

  // Don't inject our DT_NEEDED as the first dependency. This is because ASan
  // checks if ASan is the first lib loaded:
  // https://github.com/llvm/llvm-project/blob/217222abea19f7bc96e4a9f61df4a9e7599c329f/compiler-rt/lib/asan/asan_linux.cpp#L194
  int inject_idx = 1;

  /* Shift all entries down by the number of new entries. */
  setSubstr(newDynamic, 0,
            std::string(newDynamic, 0, sizeof(Elf_Dyn) * (idx + 1)));
  setSubstr(newDynamic, sizeof(Elf_Dyn) * (libs.size() + inject_idx),
            std::string(newDynamic, sizeof(Elf_Dyn) * inject_idx,
                        sizeof(Elf_Dyn) * (idx + 1)));

  /* Add the DT_NEEDED entries at the top. */
  unsigned int i = inject_idx;
  for (auto &j : libStrings) {
    Elf_Dyn newDyn;
    wri(newDyn.d_tag, DT_NEEDED);
    wri(newDyn.d_un.d_val, j);
    setSubstr(newDynamic, i * sizeof(Elf_Dyn),
              std::string((char *)&newDyn, sizeof(Elf_Dyn)));
    i++;
  }

  changed = true;
}

static std::set<std::string> neededLibsToAdd;
static bool noDefaultLib = false;

template <class ElfFile>
static void patchElf2(ElfFile &&elfFile, const FileContents &fileContents,
                      std::string fileName) {
  elfFile.addNeeded(neededLibsToAdd);

  if (elfFile.isChanged()) {
    elfFile.rewriteSections();
    writeFile(fileName, elfFile.fileContents);
  } else if (alwaysWrite) {
    debug("not modified, but alwaysWrite=true\n");
    writeFile(fileName, fileContents);
  }
}

static void patchElf() {
  for (auto fileName : fileNames) {
    auto fileContents = readFile(fileName);
    std::string outputFileName2 =
        outputFileName.empty() ? fileName : outputFileName;

    if (getElfType(fileContents).is32Bit)
      patchElf2(
          ElfFile<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr, Elf32_Addr, Elf32_Off,
                  Elf32_Dyn, Elf32_Sym, Elf32_Verneed>(fileContents),
          fileContents, outputFileName2);
    else
      patchElf2(
          ElfFile<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, Elf64_Addr, Elf64_Off,
                  Elf64_Dyn, Elf64_Sym, Elf64_Verneed>(fileContents),
          fileContents, outputFileName2);
  }
}

// TODO(andronat): Patchelf has issues with elflint
// TODO(andronat): Patchelf is writing a file. Can we do everything in-memory?
extern "C" {
void inject_needed_lib(const char *pluginpath, const char *elfpath,
                       bool debug) {
  if (debug)
    debugMode = true;

  fileNames.push_back(elfpath);
  neededLibsToAdd.insert(pluginpath);
  patchElf();
}
}

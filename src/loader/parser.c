#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>

#include "include/parser.h"

static unsigned long get_base_address(const char *map_file,
                                      const char *so_path)
{
  unsigned long start, end;
  char perms[5];
  char line[LINE_SIZE];
  char path[PATH_SIZE];
  FILE *fp;

  fp = fopen(map_file, "r");
  if (!fp)
    return 0;

  while (fgets(line, sizeof(line), fp)) {

    path[0] = '\0';

    sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]",
           &start, &end, perms, path);

    if (strstr(path, so_path)) {
      fclose(fp);
      return start;
    }
  }

  fclose(fp);
  return 0L;
}

static unsigned long get_function_offset(const char *so_path,
                                         const char *func_name)
{
  int i, j;
  int count;
  unsigned long val;
  char *strtab, *name;
  Elf64_Ehdr eh;
  Elf64_Shdr sh, str_sh;
  Elf64_Sym sym;
  FILE *fp;

  fp = fopen(so_path, "rb");
  if (!fp)
    return 0L;

  fread(&eh, 1, sizeof(eh), fp);
  fseek(fp, eh.e_shoff, SEEK_SET);

  for (i = 0; i < eh.e_shnum; i++) {
    fread(&sh, 1, sizeof(sh), fp);

    /*
     * Check if the header is for a symbol table.
     */
    if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM)
      continue;

    fseek(fp, eh.e_shoff + sh.sh_link * sizeof(Elf64_Shdr), SEEK_SET);
    fread(&str_sh, 1, sizeof(str_sh), fp);

    strtab = malloc(str_sh.sh_size);
    fseek(fp, str_sh.sh_offset, SEEK_SET);
    fread(strtab, 1, str_sh.sh_size, fp);

    count = sh.sh_size / sizeof(Elf64_Sym);
    fseek(fp, sh.sh_offset, SEEK_SET);

    for (j = 0; j < count; j++) {
      fread(&sym, 1, sizeof(sym), fp);

      /*
       * Look for a symbol representing a function.
       */
      if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC)
        continue;

      name = &strtab[sym.st_name];

      if (strcmp(name, func_name) == 0) {
        val = sym.st_value;
        free(strtab);
        fclose(fp);
        return val;
      }
    }

    free(strtab);

    fseek(fp, eh.e_shoff + (i + 1) * sizeof(Elf64_Shdr), SEEK_SET);
  }

  fclose(fp);
  return 0L;
}

unsigned long get_target_function_address(pid_t pid,
                                          const char *so_path,
                                          const char *func_name)
{
  unsigned long base_address;
  unsigned long offset;
  char maps_path[SIZE];

  snprintf(maps_path, SIZE, MAPS, pid);
  printf("Attempting to open maps file: %s\n", maps_path);

  base_address = get_base_address(maps_path, so_path);
  if (!base_address)
    return 0L;

  offset = get_function_offset(so_path, "some_function");
  if (!offset)
    return 0L;
  
  return base_address + offset;
}

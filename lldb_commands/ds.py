# MIT License

# Copyright (c) 2017 Derek Selander

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import lldb
import os
import re
import subprocess

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f ds.dcpy dcpy')
    debugger.HandleCommand('command script add -f ds.sys sys')
    if not isXcode():
        debugger.HandleCommand('settings set frame-format "\033[2mframe #${frame.index}: ${frame.pc}\033[0m{ \x1b\x5b36m${module.file.basename}\x1b\x5b39m{` \x1b\x5b33m${function.name-with-args} \x1b\x5b39m${function.pc-offset}}}\033[2m{ at ${line.file.basename}:${line.number}}\033[0m\n"')
        debugger.HandleCommand(r'''settings set thread-format "\033[2mthread #${thread.index}: tid = ${thread.id%tid}{, ${frame.pc}}\033[0m{ \033[36m'${module.file.basename}{\033[0m`\x1b\x5b33m${function.name-with-args}\x1b\x5b39m{${frame.no-debug}${function.pc-offset}}}}{ at ${line.file.basename}:${line.number}}{, name = '${thread.name}'}{, queue = '${thread.queue}'}{, activity = '${thread.info.activity.name}'}{, ${thread.info.trace_messages} messages}{, stop reason = ${thread.stop-reason}}{\nReturn value: ${thread.return-value}}{\nCompleted expression: ${thread.completed-expression}}\033[0m\n"''')
        debugger.HandleCommand(r'''settings set thread-stop-format "thread #${thread.index}{, name = '${thread.name}'}{, queue = '\033[2m${thread.queue}\033[0m'}{, activity = '${thread.info.activity.name}'}{, ${thread.info.trace_messages} messages}{, stop reason = ${thread.stop-reason}}{\nReturn value: ${thread.return-value}}{\nCompleted expression: ${thread.completed-expression}}\n"''')

        k = r'''"{${function.initial-function}{\033[36m${module.file.basename}\033[0m`}{\x1b\x5b33m${function.name-without-args}}\x1b\x5b39m:\n}{${function.changed}{${module.file.basename}\'}{${function.name-without-args}}:}{${current-pc-arrow} }\033[2m${addr-file-or-load}{ <${function.concrete-only-addr-offset-no-padding}>}:\033[0m "'''
        debugger.HandleCommand('settings set disassembly-format ' + k)


def genExpressionOptions(useSwift=False, ignoreBreakpoints=False, useID=True):
    options = lldb.SBExpressionOptions()
    options.SetIgnoreBreakpoints(ignoreBreakpoints);
    options.SetTrapExceptions(False);
    options.SetFetchDynamicValue(lldb.eDynamicCanRunTarget);
    options.SetTimeoutInMicroSeconds (30*1000*1000) # 30 second timeout
    options.SetTryAllThreads (True)
    options.SetUnwindOnError(True)
    options.SetGenerateDebugInfo(True)
    if useSwift:
        options.SetLanguage (lldb.eLanguageTypeSwift)
    else:
        options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    options.SetCoerceResultToId(useID)
    return options

def getTarget(error=None):
    target = lldb.debugger.GetSelectedTarget()
    return target

def isProcStopped():
    target = getTarget()
    process = target.GetProcess()
    if not process:
        return False

    state = process.GetState()
    if state == lldb.eStateStopped:
        return True 
    return False

def getSectionName(section):
        name = section.name
        parent = section.GetParent()
        while parent:
            name = parent.name + '.' + name
            parent = parent.GetParent()
        return name

def getSection(module=None, name=None):
    if module is None:
        path = getTarget().executable.fullpath
        module = getTarget().module[path]

    if isinstance(module, str):
        module = getTarget().module[module]
        if module is None:
            return None

    if isinstance(module, int):
        module = getTarget().modules[module]
        if module is None:
            return None

    if name is None:
        return module.sections

    sections = name.split('.')
    index = 0
    if len(sections) == 0:
        return None
    section = module.FindSection(sections[0])
    if name == section.name:
        return section
    while index < len(sections):
        name = sections[index]
        for subsec in section:
            if sections[index] in subsec.name:
                section = subsec
                if sections[-1] in subsec.name:
                    return subsec
                continue
        index += 1
    return None

def create_or_touch_filepath(filepath, contents):
    file = open(filepath, "w")
    file.write(contents)
    file.flush()
    file.close()

def dcpy(debugger, command, exe_ctx, result, internal_dict):
    res = lldb.SBCommandReturnObject()
    debugger = lldb.debugger
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand(command, res)
    if not res.Succeeded():
        result.SetError(res.GetError())
        return 
    os.system("echo '%s' | tr -d '\n'  | pbcopy" % res.GetOutput().rstrip())
    result.AppendMessage('Content copied to clipboard...')

def getSectionData(section, outputCount=0):
    name = getSectionName(section)
    loadAddr = section.addr.GetLoadAddress(getTarget())
    addr = section.addr
    size = section.size
    data = section.data
    endAddr = loadAddr + size
    addr = section.addr

    output = ([], [])
    if name == '__PAGEZERO':
        return ([0], [str(section)])
    elif name == '__TEXT':
        return ([0], [str(section)])
    elif name == '__TEXT.__objc_methname':
        return getStringsFromData(data, outputCount)
    elif name == '__TEXT.__cstring':
        return getStringsFromData(data, outputCount)
    elif  name == '__TEXT.__objc_classname':
        return getStringsFromData(data, outputCount)
    elif name == '__TEXT.__objc_methtype':
        return getStringsFromData(data, outputCount)
    elif name == '__TEXT.__const':
        pass
    elif name == '__TEXT.__swift3_typeref':
        return getStringsFromData(data, outputCount)
    elif name == '__TEXT.__swift3_fieldmd':
        pass
    elif name == '__TEXT.__swift3_assocty':
        pass
    elif name == '__TEXT.__swift2_types':
        pass
    elif name == '__TEXT.__entitlements':
        return getStringsFromData(data, outputCount)
    elif name == '__TEXT.__unwind_info':
        pass
    elif name == '__TEXT.__eh_frame':
        pass
    elif name == '__DATA':
        return ([0], [str(section)])
    elif name == '__DATA.__got':
        pass
    elif name == '__DATA.__nl_symbol_ptr':
        return getFunctionsFromData(data, outputCount)
    elif name == '__DATA.__cfstring':
        return getCFStringsFromData(data, outputCount)
    elif name == '__DATA.__const':
        pass
    elif name == '__DATA.__la_symbol_ptr':
        return getLazyPointersFromData(data, section, outputCount)
    elif name == '__DATA.__objc_classlist':
        pass
    elif name == '__DATA.__objc_protolist':
        pass
    elif name == '__DATA.__objc_imageinfo':
        pass
    elif name == '__DATA.__objc_const':
        pass
    elif name == '__DATA.__objc_selrefs':
        pass
    elif name == '__DATA.__objc_classrefs':
        pass
    elif name == '__DATA.__objc_superrefs':
        pass
    elif name == '__DATA.__objc_ivar':
        pass
    elif name == '__DATA.__objc_data':
        pass
    elif name == '__DATA.__data':
        pass
    elif name == '__DATA.__bss':
        pass
    elif name == '__DATA.__common':
        pass
    elif name == '__LINKEDIT':
        return ([0], [str(section)])

    return output

def getFunctionsFromData(data, outputCount):
    target = getTarget()
    dataArray = data.uint64
    functionList = []
    indeces = []
    print data.sint64[0]
    for i, n in enumerate(dataArray):
        if outputCount != 0 and len(functionList) > outputCount:
            break

        addr = target.ResolveLoadAddress(n)
        print i
        functionList.append(addr.symbol.name)
        indeces.append(i)

	return (indeces, functionList)


def getCFStringsFromData(data, outputCount):
    dataArray = data.uint64
    indeces = []
    stringList = []
    marker = 0
    target = getTarget()
    intType = getType('int*')

    for i, x in enumerate(dataArray):
        if i % 4 != 2:
            # 0x109b8e210: init func 0x0000000116a139e0 res/flags  0x00000000000007c8
            # 0x109b8e220: char *ptr 0x0000000109a95a42 length     0x0000000000000019
            continue
        if outputCount != 0 and len(stringList) > outputCount:
            break

        size = dataArray[i + 1]
        addr = target.ResolveFileAddress(x)
        charPointerType = getType('char', size)
        strValue = target.CreateValueFromAddress('somename', addr, charPointerType)
        stringList.append(strValue.summary)
        indeces.append(i - 2)

    return (indeces, stringList)



def generateLazyPointerScriptWithOptions(section):
    size = section.size / 4 # TODO make 32 bit compatible
    baseAddress = section.addr.module.FindSection("__TEXT").addr.GetLoadAddress(getTarget())
    la_symbol_addr = section.addr.module.FindSection("__DATA").FindSubSection("__la_symbol_ptr").addr.GetLoadAddress(getTarget())
    script = 'char retstring[' + str(size * 256) + '];\n'
    script += 'uint64_t baseAddress = ' + str(baseAddress) + ';\n'
    script += '''
@import MachO;
memset(&retstring[0], 0, sizeof(retstring));

#define INDIRECT_SYMBOL_LOCAL   0x80000000
#define INDIRECT_SYMBOL_ABS 0x40000000

#ifdef __LP64__

typedef struct mach_header_64 {
    uint32_t    magic;      /* mach magic number identifier */
    cpu_type_t  cputype;    /* cpu specifier */
    cpu_subtype_t   cpusubtype; /* machine specifier */
    uint32_t    filetype;   /* type of file */
    uint32_t    ncmds;      /* number of load commands */
    uint32_t    sizeofcmds; /* the size of all the load commands */
    uint32_t    flags;      /* flags */
    uint32_t    reserved;   /* reserved */
} ds_header;

typedef struct segment_command_64 { /* for 64-bit architectures */
    uint32_t    cmd;        /* LC_SEGMENT_64 */
    uint32_t    cmdsize;    /* includes sizeof section_64 structs */
    char        segname[16];    /* segment name */
    uint64_t    vmaddr;     /* memory address of this segment */
    uint64_t    vmsize;     /* memory size of this segment */
    uint64_t    fileoff;    /* file offset of this segment */
    uint64_t    filesize;   /* amount to map from the file */
    vm_prot_t   maxprot;    /* maximum VM protection */
    vm_prot_t   initprot;   /* initial VM protection */
    uint32_t    nsects;     /* number of sections in segment */
    uint32_t    flags;      /* flags */
} ds_segment;

typedef struct section_64 { /* for 64-bit architectures */
    char        sectname[16];   /* name of this section */
    char        segname[16];    /* segment this section goes in */
    uint64_t    addr;       /* memory address of this section */
    uint64_t    size;       /* size in bytes of this section */
    uint32_t    offset;     /* file offset of this section */
    uint32_t    align;      /* section alignment (power of 2) */
    uint32_t    reloff;     /* file offset of relocation entries */
    uint32_t    nreloc;     /* number of relocation entries */
    uint32_t    flags;      /* flags (section type and attributes)*/
    uint32_t    reserved1;  /* reserved (for offset or index) */
    uint32_t    reserved2;  /* reserved (for count or sizeof) */
    uint32_t    reserved3;  /* reserved */
} ds_section;

typedef struct nlist {
    union {
#ifndef __LP64__
        char *n_name;   /* for use when in-core */
#endif
        uint32_t n_strx;    /* index into the string table */
    } n_un;
    uint8_t n_type;     /* type flag, see below */
    uint8_t n_sect;     /* section number or NO_SECT */
    int16_t n_desc;     /* see <mach-o/stab.h> */
    uint32_t n_value;   /* value of this symbol (or stab offset) */
} dsnlist;

#else 

typedef struct mach_header {
    uint32_t    magic;      /* mach magic number identifier */
    cpu_type_t  cputype;    /* cpu specifier */
    cpu_subtype_t   cpusubtype; /* machine specifier */
    uint32_t    filetype;   /* type of file */
    uint32_t    ncmds;      /* number of load commands */
    uint32_t    sizeofcmds; /* the size of all the load commands */
    uint32_t    flags;      /* flags */
} ds_header;

typedef struct segment_command { /* for 32-bit architectures */
    uint32_t    cmd;        /* LC_SEGMENT */
    uint32_t    cmdsize;    /* includes sizeof section structs */
    char        segname[16];    /* segment name */
    uint32_t    vmaddr;     /* memory address of this segment */
    uint32_t    vmsize;     /* memory size of this segment */
    uint32_t    fileoff;    /* file offset of this segment */
    uint32_t    filesize;   /* amount to map from the file */
    vm_prot_t   maxprot;    /* maximum VM protection */
    vm_prot_t   initprot;   /* initial VM protection */
    uint32_t    nsects;     /* number of sections in segment */
    uint32_t    flags;      /* flags */
} ds_segment;

typedef struct section { /* for 32-bit architectures */
    char        sectname[16];   /* name of this section */
    char        segname[16];    /* segment this section goes in */
    uint32_t    addr;       /* memory address of this section */
    uint32_t    size;       /* size in bytes of this section */
    uint32_t    offset;     /* file offset of this section */
    uint32_t    align;      /* section alignment (power of 2) */
    uint32_t    reloff;     /* file offset of relocation entries */
    uint32_t    nreloc;     /* number of relocation entries */
    uint32_t    flags;      /* flags (section type and attributes)*/
    uint32_t    reserved1;  /* reserved (for offset or index) */
    uint32_t    reserved2;  /* reserved (for count or sizeof) */
} ds_section;

typedef struct nlist_64 {
    union {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
} dsnlist;

#endif

typedef struct symtab_command {
    uint32_t    cmd;        /* LC_SYMTAB */
    uint32_t    cmdsize;    /* sizeof(struct symtab_command) */
    uint32_t    symoff;     /* symbol table offset */
    uint32_t    nsyms;      /* number of symbol table entries */
    uint32_t    stroff;     /* string table offset */
    uint32_t    strsize;    /* string table size in bytes */
} ds_symtab_command;

typedef struct dysymtab_command {
    uint32_t cmd;   /* LC_DYSYMTAB */
    uint32_t cmdsize;   /* sizeof(struct dysymtab_command) */
    uint32_t ilocalsym; /* index to local symbols */
    uint32_t nlocalsym; /* number of local symbols */
    uint32_t iextdefsym;/* index to externally defined symbols */
    uint32_t nextdefsym;/* number of externally defined symbols */
    uint32_t iundefsym; /* index to undefined symbols */
    uint32_t nundefsym; /* number of undefined symbols */
    uint32_t tocoff;    /* file offset to table of contents */
    uint32_t ntoc;  /* number of entries in table of contents */
    uint32_t modtaboff; /* file offset to module table */
    uint32_t nmodtab;   /* number of module table entries */
    uint32_t extrefsymoff;  /* offset to referenced symbol table */
    uint32_t nextrefsyms;   /* number of referenced symbol table entries */
    uint32_t indirectsymoff; /* file offset to the indirect symbol table */
    uint32_t nindirectsyms;  /* number of indirect symbol table entries */
    uint32_t extreloff; /* offset to external relocation entries */
    uint32_t nextrel;   /* number of external relocation entries */
    uint32_t locreloff; /* offset to local relocation entries */
    uint32_t nlocrel;   /* number of local relocation entries */
} ds_dysymtab_command;

  ds_symtab_command *symtab_cmd = NULL;
  ds_dysymtab_command *dysymtab_cmd = NULL;
  char *strtab = NULL;
  
  ds_header *dsheader = (ds_header *)baseAddress;
  ds_section *la_section = NULL;

  ds_segment *cur_seg;
  struct nlist_64 *symtab = NULL;
  uintptr_t pagezero = 0;
  
  uintptr_t cur = baseAddress + sizeof(ds_header);
  for (int i = 0; i < dsheader->sizeofcmds; i++, cur += cur_seg->cmdsize) {
    cur_seg = (ds_segment *)cur;
    if (cur_seg->cmd == 0x2) { // LC_SYMTAB
      symtab_cmd = (struct symtab_command *)cur_seg;
      strtab = (char *)(symtab_cmd->stroff + baseAddress);
      symtab = (struct nlist_64 *)(symtab_cmd->symoff + baseAddress);
      
    } else if (cur_seg->cmd == 0xb) { // LC_DYSYMTAB
      dysymtab_cmd = (struct dysymtab_command *)cur_seg;
    } 
    else if (cur_seg->cmd == 0x19 && strcmp(cur_seg->segname, "__PAGEZERO") == 0) {
        pagezero = cur_seg->vmsize;
    }
    else if (cur_seg->cmd == 0x19 && strcmp(cur_seg->segname, "__DATA") == 0) {
        uintptr_t curs = cur + sizeof(ds_segment);
        for (int j = 0; j < cur_seg->nsects; j++, curs += sizeof(ds_section)) {
            ds_section *cur_sect = (ds_section*)curs; 
            if (strcmp(cur_sect->sectname, "__la_symbol_ptr") == 0) {
                la_section = (ds_section *)curs;
                break;
            }
        }
    }
  }
  
    if (!symtab_cmd || !dysymtab_cmd || !strtab || !la_section) {
        strcat(retstring, "0|||An error has occurred in parsing");
        return;
    }

  uint32_t *indirect_symbol_indices = (uint32_t *)(dysymtab_cmd->indirectsymoff + baseAddress) + la_section->reserved1;
    void **la_ptr_section = (void **)(la_section->addr + baseAddress - pagezero);
    
  for (uint i = 0; i < la_section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    if (symbol_name > strtab + symtab_cmd->strsize) {
        printf("something might of went wong...\\n");
        continue;
    }

    if (strlen(symbol_name) < 2) {
        continue;
    }

    char dsbuffer[200];
     snprintf (dsbuffer, 200, "%p|||%s...", &la_ptr_section[i],  &symbol_name[1]);
     strcat(retstring, dsbuffer);
  }

  retstring
    '''
    return script


def getLazyPointersFromData(data, section, outputCount=0):
    script = generateLazyPointerScriptWithOptions(section)

    debugger = lldb.debugger
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -l objc++ -O -- ' + script, res) 
    if res.GetError():
        return res.GetError()

    output = res.GetOutput()

    err = lldb.SBError()
    baseAddress = section.addr.GetLoadAddress(getTarget())

    lines = list(filter(lambda x: len(x) > 1, output.replace('"', '').replace('\n', '').split("...")))

    indeces = []
    stringList = []
    for line in lines:

        values = line.split('|||')
        if len(values) != 2:
            continue
        indeces.append(int(values[0], 16) - baseAddress)
        stringList.append(values[1])

    return (indeces, stringList)

    # return res.GetOutput()





def getStringsFromData(data, outputCount=0):
    dataArray = data.sint8
    indeces = []
    stringList = []
    marker = 0

    for index, x in enumerate(dataArray):
        if outputCount != 0 and len(stringList) > outputCount:
            break
        if x == 0:
            indeces.append(marker)
            stringList.append(''.join([chr(i) for i in dataArray[marker:index]]))
            marker = index + 1
    if len(stringList) == 0:
        stringList.append(''.join([chr(i) for i in data.sint8]))
        indeces.append(0)

    return (indeces, stringList)




def attrStr(msg, color='black'):
    if isXcode():
        return msg
        
    clr = {
    'cyan' : '\033[36m',
    'grey' : '\033[2m',
    'blink' : '\033[5m',
    'redd' : '\033[41m',
    'greend' : '\033[42m',
    'yellowd' : '\033[43m',
    'pinkd' : '\033[45m',
    'cyand' : '\033[46m',
    'greyd' : '\033[100m',
    'blued' : '\033[44m',
    'whiteb' : '\033[7m',
    'pink' : '\033[95m',
    'blue' : '\033[94m',
    'green' : '\033[92m',
    'yellow' : '\x1b\x5b33m',
    'red' : '\033[91m',
    'bold' : '\033[1m',
    'underline' : '\033[4m'
    }[color]
    return clr + msg + ('\x1b\x5b39m' if clr == 'yellow' else '\033[0m')

def isXcode():
    if "unknown" == os.environ.get("TERM", "unknown"):
        return True
    else: 
        return False

def getAddress(address):
    target = getTarget()
    return target.ResolveLoadAddress(address)

def getType(typeStr, count=None):
    target = getTarget()

    if typeStr.startswith('char'):
        varType = lldb.eBasicTypeChar
    elif typeStr.startswith('int'):
        varType = lldb.eBasicTypeInt
    elif typeStr.startswith('bool'):
        varType = lldb.eBasicTypeBool
    elif typeStr.startswith('double'):
        varType = lldb.eBasicTypeDouble
    elif typeStr.startswith('id'):
        varType = lldb.eBasicTypeObjCID
    elif typeStr.startswith('class'):
        varType = lldb.eBasicTypeObjCClass
    elif typeStr.startswith('void'):
        varType = lldb.eBasicTypeVoid

    t = target.GetBasicType(varType)
    if '*' in typeStr:
        t = t.GetPointerType()

    if count:
        t = t.GetArrayType(count)

    return t


def sys(debugger, command, exe_ctx, result, internal_dict):
    search =  re.search('(?<=\$\().*(?=\))', command)
    if search:
        cleanCommand = search.group(0)
        res = lldb.SBCommandReturnObject()
        interpreter = debugger.GetCommandInterpreter()
        interpreter.HandleCommand(cleanCommand, res)
        if not res.Succeeded():
            result.SetError(res.GetError())
            return
        command = command.replace('$(' + cleanCommand + ')', res.GetOutput().rstrip())
    # command = re.search('\s*(?<=sys).*', command).group(0)
    output = subprocess.Popen(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True).communicate()
    retOutput = ''
    if output[1]:
        retOutput += output[1]
    retOutput += output[0] 
    result.AppendMessage(retOutput)



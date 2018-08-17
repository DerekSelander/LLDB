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
    debugger.HandleCommand('command script add -f ds.dcpy copyz')
    debugger.HandleCommand('command script add -f ds.sys sys')
    debugger.HandleCommand('command script add -f ds.pframework pframework')
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

def pframework(debugger, command, exe_ctx, result, internal_dict):
    target = getTarget()
    res = lldb.SBCommandReturnObject()
    debugger = lldb.debugger
    interpreter = debugger.GetCommandInterpreter()
    module = target.module[command]
    if not module:
        result.SetError("Couldn't find module: {}".format(command))
        return 
    
    result.AppendMessage("\"" + module.file.fullpath + "\"")

def formatFromData(data, section, outputCount=0):
    name = getSectionName(section)
    output = ([], [])
    if name == '__PAGEZERO':
        return ([0], [str(section)])
    elif name == '__TEXT':
        return ([0], [str(section)])
    elif name == '__TEXT.__stubs':
        pass
    elif name == '__TEXT.__stub_helper':
        pass
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
        return getFunctionsFromSection(section, outputCount)
    elif name == '__DATA.__nl_symbol_ptr':
        return getFunctionsFromSection(section, outputCount)
    elif name == '__DATA.__cfstring':
        return getCFStringsFromData(data, outputCount)
    elif name == '__DATA.__const':
        pass
    elif name == '__DATA.__mod_init_func':
        return getFunctionsFromSection(section, outputCount)
    elif name == '__DATA.__la_symbol_ptr':
        return getLazyPointersFromData(data, section, outputCount)
    elif name == '__DATA.__objc_classlist':
        return getObjCClassData(section, outputCount)
    elif name == '__DATA.__objc_protolist':
        return getProtocols(section, outputCount)
    elif name == '__DATA.__objc_nlclslist':
        return getObjCClassData(section, outputCount)
    elif name == '__DATA.__objc_imageinfo':
        return ([0], [str(section)])
    elif name == '__DATA.__objc_const':
        return getSymbolsForSection(section, outputCount)
    elif name == '__DATA.__objc_selrefs':
        return getObjCSelRefs(section, outputCount)
    elif name == '__DATA.__objc_classrefs':
        return getObjCClassData(section, outputCount)
    elif name == '__DATA.__objc_superrefs':
        return getObjCClassData(section, outputCount)
    elif name == '__DATA.__objc_ivar':
        return getIvars(section, outputCount)
    elif name == '__DATA.__objc_data':
        pass
    elif name == '__DATA.__data':
        return getSymbolsForSection(section, outputCount, False)
    elif name == '__DATA.__bss':
        return getSymbolsForSection(section, outputCount, False)
    elif name == '__DATA.__common':
        return getSymbolsForSection(section, outputCount, False)
    elif name == '__LINKEDIT':
        return getLINKEDITData(section)

    return output

def getSymbolsForSection(section, outputCount, shouldFilterDataOnly = True):
    # Grab all the DATA related symbols
    module = section.addr.module
    target = getTarget()
    section_load_addr = section.GetLoadAddress(target)

    if shouldFilterDataOnly:
        symbols = [i for i in module.symbols if i.type == 4]
    else:
        symbols = module.symbols
    indeces = []
    symbolList = []
    descriptions = []

    process = lldb.process 


            #       error = lldb.SBError()
        # ptr = process.ReadPointerFromMemory(loadAddr + i * ptrsize, error)
        # if error.success == True:

        #     sec = target.ResolveLoadAddress(ptr).section
        #     if sec.IsValid():
        #         if sec.name == "__stub_helper":
        #             descriptions.append("-")
        #         else:
        #             descriptions.append("+")
        #     else:
        #         descriptions.append(None)


        # stringList.append(retstr)
    err = lldb.SBError()
    for symbol in symbols:
        if symbol.GetStartAddress().GetSection() == section:
            symbolList.append(symbol.name)
            symbol_load_address = symbol.GetStartAddress().GetLoadAddress(target)
            symbol_end_address = symbol.GetEndAddress().GetLoadAddress(target)

            size = symbol_end_address-symbol_load_address
            indeces.append((symbol_load_address - section_load_addr, size))
            
            if size % 4 != 0 or size > 8:
                descriptions.append(None)
                continue

            read_memory =  "{0:#0{1}x}".format(process.ReadUnsignedFromMemory(symbol_load_address, size, err), size *2)
            if err.success == True:
                descriptions.append(read_memory)
            else:
                print ("error parsing memory {}, {}".format(symbol_load_address, size))
                descriptions.append(None)

    return (indeces, symbolList, descriptions)

def getIvars(section, outputCount):
    target = getTarget()
    indeces = []
    stringList = []

    ptrsize = getType("void*").GetByteSize()
    sz = section.GetByteSize() / ptrsize
    addr = section.GetLoadAddress(target)
    script = "int dssize = {};\nuintptr_t *ivarOffsets[{}];\nuintptr_t **ivarPointer = (uintptr_t**){};".format(sz, sz, addr)
    script += r'''
memset(&ivarOffsets, 0, sizeof(ivarOffsets));
for (int i = 0; i < dssize; i++) {
    ivarOffsets[i] = ivarPointer[i];
}
ivarOffsets'''
    val = target.EvaluateExpression(script, genExpressionOptions(False, True, True))
    for i in  range(val.GetNumChildren()):
        x = val.GetChildAtIndex(i)
        indeces.append(i * ptrsize)
        stringList.append(hex(x.unsigned))

    return (indeces, stringList) 

def getProtocols(section, outputCount):
    target = getTarget()
    indeces = []
    stringList = []

    ptrsize = getType("void*").GetByteSize()
    sz = section.GetByteSize() / ptrsize
    addr = section.GetLoadAddress(target)
    script = "int dssize = {};\nchar *protNames[{}];\nClass *clsPointer = (Class*){};".format(sz, sz, addr)
    script += r'''
@import ObjectiveC;
memset(&protNames, 0, sizeof(protNames));
for (int i = 0; i < dssize; i++) {
    protNames[i] = (char*)protocol_getName(clsPointer[i]);
}
protNames'''
    val = target.EvaluateExpression(script, genExpressionOptions(False, True, True))
    for i in  range(val.GetNumChildren()):
        x = val.GetChildAtIndex(i)
        indeces.append(i * ptrsize)
        stringList.append(x.summary.replace("\"", ""))

    return (indeces, stringList)

def getLINKEDITData(section):
    addr = section.addr
    module = addr.GetModule()
    target = getTarget()
    fileHeaderAddr = module.GetObjectFileHeaderAddress().GetLoadAddress(target)

    LINKEDITAddr = section.GetLoadAddress(target)
    indeces = []
    stringList = []

    script = generateMachOHeaders()
    script += 'uintptr_t baseAddress = (uintptr_t){};\n'.format(fileHeaderAddr)
    # script += 'uintptr_t linkeditAddress = (uintptr_t){};\n'.format(LINKEDITAddr)
    script += r'''

@import Foundation;
ds_symtab_command *symtab_cmd = NULL;
ds_dysymtab_command *dysymtab_cmd = NULL;
char *strtab = NULL;

ds_header *dsheader = (ds_header *)baseAddress;
ds_section *la_section = NULL;

ds_segment *cur_seg = NULL;
ds_segment *linkeditSegment = NULL;
struct nlist_64 *symtab = NULL;
uintptr_t pagezero = 0;

uintptr_t cur = baseAddress + sizeof(ds_header);
for (int i = 0; i < dsheader->ncmds; i++, cur += cur_seg->cmdsize) {
    cur_seg = (ds_segment *)cur;
    if (cur_seg->cmd == 0x2) { // LC_SYMTAB
        symtab_cmd = (ds_symtab_command *)cur_seg;
      
    } else if (cur_seg->cmd == 0xb) { // LC_DYSYMTAB
        dysymtab_cmd = (ds_dysymtab_command *)cur_seg;
    } 
    else if (cur_seg->cmd == 0x19 && strcmp(cur_seg->segname, "__LINKEDIT") == 0) {
        // pagezero = cur_seg->vmsize;
        linkeditSegment = cur_seg;
    }
    else if (cur_seg->cmd == 0x19 && strcmp(cur_seg->segname, "__PAGEZERO") == 0) {
        pagezero = cur_seg->vmsize;
    }
}

strtab = (char *)(symtab_cmd->stroff + baseAddress + linkeditSegment->vmaddr - linkeditSegment->fileoff - pagezero);
symtab = (struct nlist_64 *)(symtab_cmd->symoff + baseAddress + linkeditSegment->vmaddr - linkeditSegment->fileoff - pagezero);
uintptr_t linkedit_base = baseAddress + linkeditSegment->vmaddr - linkeditSegment->fileoff - pagezero;

NSMutableString *returnString = [NSMutableString new];
if (symtab_cmd) {
    [returnString appendString:@"LC_SYMTAB\n"];
    [returnString appendString:(id)[NSString stringWithFormat:@"\t[%012p] symtab (%d entries)\n", symtab, symtab_cmd->nsyms]];
    [returnString appendString:(id)[NSString stringWithFormat:@"\t[%012p] strtab (size %d)\n", strtab, symtab_cmd->strsize]];
} 

if (dysymtab_cmd) {
    [returnString appendString:@"LC_DYSYMTAB\n"];
    if (dysymtab_cmd->nlocalsym > 0) {
        [returnString appendString:[NSString stringWithFormat:@"\t[%p] local symbols (%d entries, index %d)\n", &symtab[dysymtab_cmd->ilocalsym],  dysymtab_cmd->nlocalsym, dysymtab_cmd->ilocalsym]];
    } else { 
        [returnString appendString:@"\tno local symbols\n"];
    }

    if (dysymtab_cmd->nextdefsym > 0) {
        [returnString appendString:[NSString stringWithFormat:@"\t[%p] external symbols (%d entries, index %d)\n", &symtab[dysymtab_cmd->iextdefsym], dysymtab_cmd->nextdefsym, dysymtab_cmd->iextdefsym]];
    } else { 
        [returnString appendString:@"\tno external symbols\n"];
    }

    if (dysymtab_cmd->nundefsym > 0) {
        [returnString appendString:[NSString stringWithFormat:@"\t[%p] undefined symbols (%d entries, index %d)\n", &symtab[dysymtab_cmd->iundefsym], dysymtab_cmd->nundefsym, dysymtab_cmd->iundefsym]];
    } else { 
        [returnString appendString:@"\tno undefined symbols\n"];
    }
    
    if (dysymtab_cmd->ntoc > 0) {
        [returnString appendString:[NSString stringWithFormat:@"\t[%p] TOC (%d entries, index %d)\n", &symtab[dysymtab_cmd->tocoff], dysymtab_cmd->ntoc, dysymtab_cmd->tocoff]];
    } else { 
        [returnString appendString:@"\tno TOC\n"];
    }

    if (dysymtab_cmd->nmodtab > 0) {
        [returnString appendString:[NSString stringWithFormat:@"\t[%p] modtab (%d entries, index %d)\n", &symtab[dysymtab_cmd->modtaboff], dysymtab_cmd->nmodtab, dysymtab_cmd->modtaboff]];
    } else { 
        [returnString appendString:@"\tno modtab\n"];
    }

    if (dysymtab_cmd->nindirectsyms > 0) {
        [returnString appendString:[NSString stringWithFormat:@"\t[%p] indirect symbols (%d entries, index %d)\n", &symtab[dysymtab_cmd->indirectsymoff], dysymtab_cmd->nindirectsyms, dysymtab_cmd->indirectsymoff]];
    } else { 
        [returnString appendString:@"\tno indirect symbols\n"];
    }
}  
returnString
    '''
    val = target.EvaluateExpression(script, genExpressionOptions(False, True, True))
    indeces.append(0)
    stringList.append(val.description)

    return (indeces, stringList)




def getObjCClassData(section, outputCount=0):

    target = getTarget()
    indeces = []
    stringList = []

    ptrsize = getType("void*").GetByteSize()
    sz = section.GetByteSize() / ptrsize
    addr = section.GetLoadAddress(target)
    script = "int dssize = {};\nchar *classNames[{}];\nClass *clsPointer = (Class*){};".format(sz, sz,  addr)
    script += r'''
memset(&classNames, 0, sizeof(classNames))
for (int i = 0; i < dssize; i++) {
    classNames[i] = (char*)class_getName(clsPointer[i]);
}
classNames'''
    val = target.EvaluateExpression(script, genExpressionOptions(False, True, True))

    for i in  range(val.GetNumChildren()):
        x = val.GetChildAtIndex(i)
        indeces.append(i * ptrsize)
        stringList.append(x.summary.replace("\"", ""))

    return (indeces, stringList)

def getSectionData(section, outputCount=0):
    # loadAddr = section.addr.GetLoadAddress(getTarget())
    # addr = section.addr
    # size = section.size
    data = section.data

    # endAddr = loadAddr + size
    # addr = section.addr
    return formatFromData(data, section, outputCount)

def getFunctionsFromSection(section, outputCount=0):
    target = getTarget()
    ptrsize = getType("void*").GetByteSize()

    functionList = []
    indeces = []
    descriptions = []

    size = section.GetByteSize() / ptrsize
    baseAddress = section.addr.GetLoadAddress(target)

    script = "uintptr_t retstring[{}];\n".format(size)
    script += "uintptr_t *baseAddress = (uintptr_t *){};\n".format(baseAddress)
    script += "int size = {};\n".format(size)
    script += r'''
    memset(&retstring, 0, sizeof(retstring));

    for (int i = 0; i < size; i++) {
        retstring[i] = baseAddress[i];
    }
    retstring
'''
    options = genExpressionOptions(False, True, True)
    val = target.EvaluateExpression(script, options)

    for i, x in enumerate(val):
        indeces.append(i * ptrsize)
        descriptions.append("{}".format(hex(x.unsigned)))
        retval = ""
        addr = target.ResolveLoadAddress(x.unsigned)
        if addr.symbol.IsValid():
            retval += " {}".format(addr.symbol.name)
        functionList.append(retval)

    return (indeces, functionList, descriptions)

def getObjCSelRefs(section, outputCount):
    target = getTarget()
    ptrsize = getType("char*").GetByteSize()
    sz = section.GetByteSize() / ptrsize
    addr = target.ResolveLoadAddress(section.GetLoadAddress(target))
    ty = getType("char*", sz)
    val = target.CreateValueFromAddress("somename", addr, ty)

    indeces = []
    stringList = []
    descriptions = []

    for i, x in enumerate(val):
        indeces.append(i * ptrsize)
        descriptions.append("{}".format(hex(x.deref.GetLoadAddress())))
        stringList.append("{}".format(x.summary))

    return (indeces, stringList, descriptions)


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

def generateMachOHeaders():
    return r'''

@import MachO;

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

typedef struct  {
    uint32_t    cmd;        /* LC_SYMTAB */
    uint32_t    cmdsize;    /* sizeof(struct symtab_command) */
    uint32_t    symoff;     /* symbol table offset */
    uint32_t    nsyms;      /* number of symbol table entries */
    uint32_t    stroff;     /* string table offset */
    uint32_t    strsize;    /* string table size in bytes */
} ds_symtab_command;

typedef struct  {
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
    '''

def generateLazyPointerScriptWithOptions(section):
    ptrsize = getType("void*").GetByteSize()
    size = section.GetByteSize() / ptrsize
    baseAddress = section.addr.module.FindSection("__TEXT").addr.GetLoadAddress(getTarget())
    linkeditAddress = section.addr.module.FindSection("__LINKEDIT").addr.GetLoadAddress(getTarget())
    la_symbol_addr = section.addr.module.FindSection("__DATA").FindSubSection("__la_symbol_ptr").addr.GetLoadAddress(getTarget())
    script = 'char *retstring[' + str(size) + '];\n'
    script += 'uint64_t baseAddress = (uintptr_t)' + str(baseAddress) + ';\n'
    script += 'uint64_t linkeditAddress = (uintptr_t)' + str(linkeditAddress) + ';\n'
    script += generateMachOHeaders()
    script += '''
  memset(&retstring, 0, sizeof(retstring));

  ds_symtab_command *symtab_cmd = NULL;
  ds_dysymtab_command *dysymtab_cmd = NULL;
  char *strtab = NULL;
  
  ds_header *dsheader = (ds_header *)baseAddress;
  ds_section *la_section = NULL;

  ds_segment *cur_seg = NULL;
  ds_segment *linkeditSegment = NULL;
  struct nlist_64 *symtab = NULL;
  uintptr_t pagezero = 0;
  
  uintptr_t cur = baseAddress + sizeof(ds_header);
  for (int i = 0; i < dsheader->ncmds; i++, cur += cur_seg->cmdsize) {
    cur_seg = (ds_segment *)cur;
    if (cur_seg->cmd == 0x2) { // LC_SYMTAB
      symtab_cmd = (ds_symtab_command *)cur_seg;

    } else if (cur_seg->cmd == 0xb) { // LC_DYSYMTAB
      dysymtab_cmd = (ds_dysymtab_command *)cur_seg;
    } 
    else if (cur_seg->cmd == 0x19 && strcmp(cur_seg->segname, "__LINKEDIT") == 0) {
        linkeditSegment = cur_seg;
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
  
  uintptr_t linkedit_base = baseAddress + linkeditSegment->vmaddr - linkeditSegment->fileoff - pagezero;
  strtab = (char *)(symtab_cmd->stroff + linkedit_base);
  symtab = (struct nlist_64 *)(symtab_cmd->symoff + linkedit_base);

    if (!symtab_cmd || !dysymtab_cmd || !strtab || !la_section) {
        //strcat(retstring, "0|||An error has occurred in parsing");
        return;
    }

  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);
  uint32_t *indirect_symbol_indices = (uint32_t *)(indirect_symtab + la_section->reserved1);
  for (uint i = 0; i < la_section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    if (symbol_name > strtab + symtab_cmd->strsize) {
        //printf("something might of went wong...\\n");
        //printf("baseaddress %p, symoff %p, indrectsymoff %p, reserved1 %p, %p %i", baseAddress, dysymtab_cmd->indirectsymoff, la_section->reserved1, indirect_symbol_indices, i);
        continue;
    }

    if (strlen(symbol_name) < 2) {
        continue;
    }
     retstring[i] = &symbol_name[1];
  }

  retstring
    '''
    return script

def getLazyPointersFromData(data, section, outputCount=0):
    script = generateLazyPointerScriptWithOptions(section)
    target = getTarget()
    indeces = []
    stringList = []
    descriptions = []

    ptrsize = getType("void*").GetByteSize()

    options = genExpressionOptions(False, True, True)
    val = target.EvaluateExpression(script, options)

    # for dbg'ing 
    # lldb.debugger.HandleCommand('exp -l objc++ -O -g -- ' + script)
        # print(res)

    process = target.GetProcess()
    loadAddr = section.addr.GetLoadAddress(target)


    for i in range(val.GetNumChildren()):
        x = val.GetChildAtIndex(i)
        indeces.append(i * ptrsize)
        retstr = x.summary.replace("\"", "")

        error = lldb.SBError()
        ptr = process.ReadPointerFromMemory(loadAddr + i * ptrsize, error)
        if error.success == True:

            sec = target.ResolveLoadAddress(ptr).section
            if sec.IsValid():
                if sec.name == "__stub_helper":
                    descriptions.append("-")
                else:
                    descriptions.append("+")
            else:
                descriptions.append(None)


        stringList.append(retstr)
    return (indeces, stringList, descriptions)

def getStringsFromData(_data, outputCount=0):
    indeces = []
    stringList = []
    target = getTarget()

    #  Hack, f it
    if outputCount == 1:
        err = lldb.SBError()
        val = target.EvaluateExpression('(char *){}'.format(_data.GetAddress(err, 0)), genExpressionOptions())
        print (val)

    #  Force conversion of "unknown" data to known of char**
    t = target.GetBasicType(lldb.eBasicTypeChar).GetPointerType()
    data = _data

    vl = target.CreateValueFromData("__ds_unused", _data, t)
    if not vl.IsValid():
        print("SBValue not valid")
        return (indeces, stringList)

    dataArray = data.sint8
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
    for _ in xrange(typeStr.count("*")):
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
        interpreter.HandleCommand(cleanCommand, res, True)
        if not res.Succeeded():
            result.SetError(res.GetError())
            return

        if not res.HasResult():
            # result.SetError("NoneType for {}".format(cleanCommand))
            return

        command = command.replace('$(' + cleanCommand + ')', res.GetOutput().rstrip())
    # command = re.search('\s*(?<=sys).*', command).group(0)
    my_env = os.environ.copy()
    my_env["PATH"] = "/usr/local/bin:" + my_env["PATH"]
    output = subprocess.Popen(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, env=my_env).communicate()
    retOutput = ''
    if output[1]:
        retOutput += output[1]
    retOutput += output[0] 
    result.AppendMessage(retOutput)



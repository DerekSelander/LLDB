

import lldb
import os
import shlex
import optparse
import ds

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f section.handle_command section -h "Mach-O segment/section helper"')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Documentation for how to use section goes here 
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    # Uncomment if you are expecting at least one argument
    # clean_command = shlex.split(args[0])[0]

    target = exe_ctx.target
    sections = None

    if len(args) == 0:
        options.summary = True
        sections = [i for i in ds.getSection()]
    elif len(args) == 1:
        module = args[0] if target.module[args[0]] else None
        segment = args[0] if not module else None
        if segment and '.' in segment:
            if module:
                sections = ds.getSection(module=args[0], name=None)
            else:
                sections = [ds.getSection(module=None, name=args[0])]
        else:
            # module = args[0] if target.module[args[0]] else None
            options.summary = True
            if module:
                sections = ds.getSection(module=args[0], name=None)
            elif args[0] == '__PAGEZERO':
                sections = ds.getSection(module=None, name=args[0])
            else:
                _sz = ds.getSection(module=None, name=args[0])

                if isinstance(_sz, lldb.SBSection) and _sz.name != "__LINKEDIT":
                    sections = [i for i in _sz]
                elif isinstance(_sz, lldb.SBSection) and _sz.name == "__LINKEDIT":
                    options.summary = False
                    sections = [_sz]
    elif len(args) == 2:
        if '.' in args[1]:
            sections = [ds.getSection(args[0], args[1])]
        else:
            _sz = ds.getSection(args[0], args[1])
            if isinstance(_sz, lldb.SBSection) and _sz.name != "__LINKEDIT":
                options.summary = True
                sections = [i for i in _sz]
            elif isinstance(_sz, lldb.SBSection) and _sz.name == "__LINKEDIT":
                options.summary = False
                sections = [_sz]

    if isinstance(sections, lldb.SBSection) and sections.GetNumSubSections() == 0:
        output = str(sections)
    elif sections is not None:
        output = parseSection(sections, options, target)
    else:
        if len(args) == 2:
            output = "parsing module: \"{}\", in section \"{}\"".format(args[0], args[1])
        else:
            output = "parsing module: \"{}\", in section \"{}\"".format(target.executable.basename, args[0])
        result.SetError(output)
        return 

    result.AppendMessage(output)

def parseSection(sections, options, target):
    output = ''
    # sections is a list here
    if len(sections) > 0:
        for section in sections:
            name = ds.getSectionName(section)
            loadAddr = section.addr.GetLoadAddress(target)
            addr = section.addr
            size = section.size
            data = section.data
            endAddr = loadAddr + size
            addr = section.addr

            if options.summary:
                moduleName  = addr.module.file.basename
                if name == '__PAGEZERO':
                    loadAddr = 0
                    endAddr = size
                output += ds.attrStr('[' + '{0:#016x}'.format(loadAddr) + '-' + '{0:#016x}'.format(endAddr) + '] ', 'cyan')
                output += ds.attrStr("{0:#012x}".format(size), 'grey') + ' '
                output += ds.attrStr(moduleName, 'yellow') + '`'
                output += ds.attrStr(name, 'cyan') + '\n'
                continue

            returnType = ds.getSectionData(section, options.count)

            # Ok, I really need to rewrite this, but whatever
            if isinstance(returnType, tuple):
                (indeces, sectionData) = returnType
                for index, x in enumerate(sectionData):
                    if options.count != 0 and index  >= options.count:
                        break

                    if options.load_address:
                        output += ds.attrStr(hex(loadAddr + indeces[index]), 'yellow') + ' '

                    output += ds.attrStr(str(x), 'cyan') + '\n'
            elif isinstance(returnType, str):
                output += returnType

    return output

def generate_option_parser():
    usage = "usage: %prog [options] Dump Mach-O sections in a module"
    parser = optparse.OptionParser(usage=usage, prog="section")
    parser.add_option("-l", "--load_address",
                      action="store_true",
                      default=False,
                      dest="load_address",
                      help="Show load addresses in proc")

    parser.add_option("-s", "--summary",
                      action="store_true",
                      default=False,
                      dest="summary",
                      help="Summary for modules")

    parser.add_option("-f", "--format",
                      action="store",
                      default=None,
                      dest="format",
                      help="format")

    parser.add_option("-c", "--count",
                      action="store",
                      default=0,
                      type="int",
                      dest="count",
                      help="Max count of items to print out")
    return parser
    

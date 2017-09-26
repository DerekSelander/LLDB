

import lldb
import os
import shlex
import optparse
import ds

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f section.handle_command section')

def handle_command(debugger, command, result, internal_dict):
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

    if len(args) == 0:
        options.summary = True
        sections = [i for i in ds.getSection()]
    elif len(args) == 1:
        module = args[0] if ds.getTarget().module[args[0]] else None
        segment = args[0] if not module else None
        if segment and '.' in segment:
            if module:
                sections = ds.getSection(module=args[0], name=None)
            else:
                sections = [ds.getSection(module=None, name=args[0])]
        else:
            # module = args[0] if ds.getTarget().module[args[0]] else None
            options.summary = True
            if module:
                sections = ds.getSection(module=args[0], name=None)
            else:
                sections = [i for i in ds.getSection(module=None, name=args[0])]
    elif len(args) == 2:
        if '.' in args[1]:
            sections = [ds.getSection(args[0], args[1])]
        else:
            options.summary = True
            sections = [i for i in ds.getSection(args[0], args[1])]


    output = parseSection(sections, options)
    result.AppendMessage(output)


def parseSection(sections, options):
    output = ''
    for section in sections:
        # if section 

        name = ds.getSectionName(section)
        loadAddr = section.addr.GetLoadAddress(ds.getTarget())
        addr = section.addr
        size = section.size
        data = section.data
        endAddr = loadAddr + size
        addr = section.addr
        if options.summary:
            moduleName  = addr.module.file.basename
            # bug TODO figure why pagezero is wonky 
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
    
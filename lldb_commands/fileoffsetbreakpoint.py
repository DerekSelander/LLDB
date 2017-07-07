

import lldb
import os
import shlex
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f fileoffsetbreakpoint.handle_command lbr')

def handle_command(debugger, command, result, internal_dict):
    '''
    Creates a breakpoint on the fileoffset of a module and resolves 
    to the load address in memory. 

    lbr ModuleName OffsetAddress
    i.e. lbr UIKit 0x12343

    Cheers
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(__doc__)
        return

    if len(args) != 2:
        result.SetError(parser.usage)
        return 

    target = debugger.GetSelectedTarget()
    module = target.module[args[0]]
    try: 
        offset = long(args[1], 16)
    except:
        result.SetError('Second argument needs to a number')
        return 

    if module is None:
        result.SetError("Can't find module {}. Womp Womp... Use image list -b to see all modules".format(module))
        return

    addr = module.ResolveFileAddress(offset)
    breakpoint = target.BreakpointCreateBySBAddress(addr)

    if addr.symbol:
        name = addr.symbol.name
        loadAddr = hex(addr.GetLoadAddress(target))
        result.AppendMessage('breakpoint created, {} {}'.format(loadAddr, name))


def generate_option_parser():
    usage = handle_command.__doc__
    parser = optparse.OptionParser(usage=usage, prog="fileoffsetbreakpoint")
    parser.add_option("-m", "--module",
                      action="store",
                      default=None,
                      dest="module",
                      help="This is a placeholder option to show you how to use options with strings")
    parser.add_option("-c", "--check_if_true",
                      action="store_true",
                      default=False,
                      dest="store_true",
                      help="This is a placeholder option to show you how to use options with bools")
    return parser
    
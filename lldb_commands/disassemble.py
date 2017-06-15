

import lldb
import os
import shlex
import optparse
import ds

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f disassemble.handle_command dd')

def handle_command(debugger, command, result, internal_dict):
    '''
    Disassemble with colors! Terminal only
    '''

    command_args = shlex.split(command, posix=False)
    target = ds.getTarget()
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    if len(args) == 0:
        sym = ds.getFrame().GetSymbol()
    else:
        sym = ds.getTarget().ResolveLoadAddress(long(args[0], 16)).GetSymbol()

    instructions = sym.GetInstructions(target)
    output = ds.attrStr(sym.addr.module.file.basename + ', ' + sym.name, 'cyan') + '\n'
    counter = 0

    if len(instructions) == 0:
        return
    startAddress = instructions.GetInstructionAtIndex(0).GetAddress().GetLoadAddress(target)
    for inst in instructions:
        line = ds.attrStr(str(counter).ljust(4), 'grey')
        counter += 1
        offset = str(inst.addr.GetLoadAddress(target) - startAddress)
        loadaddr = ds.attrStr(hex(inst.addr.GetLoadAddress(target)) + (' <+' + offset + '>:').ljust(8), 'grey')
        mnemonic = ds.attrStr(inst.mnemonic.ljust(5), 'red')
        operands = ds.attrStr(inst.operands, 'bold')
        comments = ds.attrStr(inst.comment, 'green')
        if options.memory:
            tmp = ' '.join([hex(i).replace('0x', '').zfill(2) for i in inst.GetData(lldb.target).uint8s])
            mem = ds.attrStr(tmp, 'cyan')
        else:
            mem = ''

        output += '{} {} {} {} {} {}\n'.format(line, loadaddr, mem, mnemonic, operands, comments)

    result.AppendMessage(output)


def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="disassemble")
    parser.add_option("-m", "--memory",
                      action="store_true",
                      default=False,
                      dest="memory",
                      help="Shows the memory at this address")
    return parser
    
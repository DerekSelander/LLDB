

import lldb
import os
import shlex
import optparse
import ds
import re

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
    output = ds.attrStr(str(sym.addr.module.file.basename) + ', ', 'cyan') + ds.attrStr(str(sym.name), 'yellow') + '\n'
    counter = 0

    if len(instructions) == 0:
        return
    startAddress = instructions.GetInstructionAtIndex(0).GetAddress().GetLoadAddress(target)

    frame = ds.getFrame()

    branches = []
    offsetSizeDict = {}
    for inst in instructions:
        line = ds.attrStr(str(counter).ljust(4), 'grey')
        offset = str(inst.addr.GetLoadAddress(target) - startAddress)
        branch = (ds.attrStr('*', 'yellow') if inst.is_branch else ' ')
        pc = ds.attrStr('-> ', 'grey') if frame.addr == inst.addr else '   '

        loadaddr = ds.attrStr(hex(inst.addr.GetLoadAddress(target)) + (' <+' + offset + '>:').ljust(8), 'grey')
        mnemonic = ds.attrStr(inst.mnemonic.ljust(5), 'red')
        operands = ds.attrStr(inst.operands, 'bold')
        comments = ds.attrStr(inst.comment, 'cyan')

        # TODO x64 only, need arm64
        if 'rip' in inst.operands:
            nextInst = instructions[counter + 1]
            m = re.search(r"(?<=\[).*(?=\])", inst.operands)
            pcComment = ''
            if m:
                nextPCAddr = hex(nextInst.addr.GetLoadAddress(target))
                commentLoadAddr = eval(m.group(0).replace('rip', nextPCAddr))
                pcComment += ds.attrStr(hex(commentLoadAddr), 'green')
                if options.verbose:
                    pcComment += ' ' + ds.attrStr(str(ds.getTarget().ResolveLoadAddress(commentLoadAddr).section), 'green')
        else:
            pcComment = ''




        match = re.search('(?<=\<\+)[0-9]+(?=\>)', inst.comment)
        offsetSizeDict[offset] = counter
        if options.show_branch and inst.is_branch and match:
            branches.append((counter, int(match.group(0))))

        if options.memory:
            tmp = ' '.join([hex(i).replace('0x', '').zfill(2) for i in inst.GetData(lldb.target).uint8s])
            mem = ds.attrStr(tmp, 'cyan')
        else:
            mem = ''

        formatter = '{}' if options.show_branch else ''
        output += '{}{}{} {}{} {} {} {} {} {}\n'.format(pc, branch, line, formatter, loadaddr, mem, mnemonic, operands, comments, pcComment)
        counter += 1


    if options.show_branch:
        branchLines = generateBranchLines(branches, counter, offsetSizeDict)
        for i, line in enumerate(output.split('\n')):
            output += line.format(branchLines[i]) + '\n'


    result.AppendMessage(output)

def generateBranchLines(branches, count, offsetSizeDict):
    lines = ['' for i in range(count)]
    multiplier = 1
    for branch in branches:
        inc = -1 if branch[0] > branch[1] else 1
        ceiling = offsetSizeDict[str(branch[1])]
        for i in range(branch[0], ceiling, inc):
            print (str(branch) + " " + str(i) + ' ' + str(len(lines)))
            if i == branch[1]:
                lines[i] += '>' + '-' * multiplier
            elif i == branch[0]:
                lines[i] += '-' + '-' * multiplier
            else:
                lines[i] += ' ' * multiplier + '|'

    return [i[::-1] for i in lines]

def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="disassemble")
    parser.add_option("-m", "--memory",
                      action="store_true",
                      default=False,
                      dest="memory",
                      help="Shows the memory at this address")

    parser.add_option("-b", "--show_branch",
                      action="store_true",
                      default=False,
                      dest="show_branch",
                      help="Show the branches within the function")

    parser.add_option("-v", "--verbose",
                  action="store_true",
                  default=False,
                  dest="verbose",
                  help="Verbose commentary")
    return parser
    
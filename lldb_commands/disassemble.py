

import lldb
import os
import shlex
import optparse
import ds
import re

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f disassemble.handle_command dd -h "Alternative to LLDB\'s disassemble cmd"')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Disassemble with colors! Terminal only
    '''

    command_args = shlex.split(command, posix=False)
    target = exe_ctx.target
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    output = ''


        
    if options.search_functions:
        query = options.search_functions
        symbol_context_list = target.FindGlobalFunctions(query, 0, lldb.eMatchTypeRegex)    
        for symContext in symbol_context_list:
            output += generateAssemblyFromSymbol(symContext.symbol, options, exe_ctx)
    elif len(args) == 0:
        sym = exe_ctx.frame.symbol
        output += generateAssemblyFromSymbol(sym, options, exe_ctx)
    elif args[0].startswith('0x'):
        sym = target.ResolveLoadAddress(long(args[0], 16)).GetSymbol()
        output += generateAssemblyFromSymbol(sym, options, exe_ctx)
    elif args[0].isdigit():
        sym = target.ResolveLoadAddress(long(args[0])).GetSymbol()
        output += generateAssemblyFromSymbol(sym, options, exe_ctx)
    else:
        cleanCommand = ' '.join(args)
        symList = target.FindGlobalFunctions(cleanCommand, 0, lldb.eMatchTypeNormal)    
        if symList.GetSize() == 0:
            result.SetError(ds.attrStr("Couldn't find any matches for \"{}\"".format(cleanCommand), 'red'))
            return
        sym = symList
        output += generateAssemblyFromSymbol(symList.GetContextAtIndex(0).symbol, options, exe_ctx)

    result.AppendMessage(output)

def generateAssemblyFromSymbol(sym, options, exe_ctx):
    target = exe_ctx.target
    frame = exe_ctx.GetFrame()
    instructions = sym.GetInstructions(target)
    output = ds.attrStr(str(sym.addr.module.file.basename) + ', ', 'cyan') + ds.attrStr(str(sym.name), 'yellow') + '\n'
    counter = 0

    if len(instructions) == 0:
        return
    startAddress = instructions.GetInstructionAtIndex(0).GetAddress().GetLoadAddress(target)

    branches = []
    offsetSizeDict = {}
    grepSearch = False 
    for inst in instructions:
        line = ds.attrStr(str(counter).ljust(4), 'grey')
        offset = str(inst.addr.GetLoadAddress(target) - startAddress)
        branch = (ds.attrStr('*', 'yellow') if inst.is_branch else ' ')
        pc = ds.attrStr('-> ', 'red') if frame.addr == inst.addr else '   '

        loadaddr = ds.attrStr(hex(inst.addr.GetLoadAddress(target)) + (' <+' + offset + '>:').ljust(8), 'grey')
        mnemonic = ds.attrStr(inst.GetMnemonic(target).ljust(5), 'red')
        mnemonicStr = inst.GetMnemonic(target).ljust(5)
        if len(inst.GetOperands(target).split(',')) > 1:
            ops = inst.GetOperands(target).split(',')
            operands = ds.attrStr(ops[0], 'bold') + ', ' + ds.attrStr(ops[1], 'yellow')
        else: 
            operands = ds.attrStr(inst.GetOperands(target), 'bold')
        comments = ds.attrStr(inst.GetComment(target), 'cyan')

        if options.grep_functions:
            if re.search(options.grep_functions, comments):
                grepSearch = True

        # TODO x64 only, need arm64
        if 'rip' in inst.GetOperands(target):
            nextInst = instructions[counter + 1]
            m = re.search(r"(?<=\[).*(?=\])", inst.GetOperands(target))
            pcComment = ''



            if m and nextInst:
                nextPCAddr = hex(nextInst.addr.GetLoadAddress(target))
                commentLoadAddr = eval(m.group(0).replace('rip', nextPCAddr))

                addr = target.ResolveLoadAddress(commentLoadAddr)
                showComments, modName = generateDescriptionByAddress(addr, target)
                if not showComments:
                    comments = ''

                if modName in comments:
                    comments = ''
                pcComment += ds.attrStr('; ' + modName, 'green')
                # interpreter.HandleCommand('image lookup -a ' + nextPCAddr, res)

                # # m = re.search('(?<=\().*(?=\s)', res.GetOutput())
                # # if m:
                # #     pcComment += ds.attrStr(' ' + m.group(0), 'green')

                # m = re.search('(?<=Summary\:\s).*$', res.GetOutput())
                # if m:
                #     pcComment += ds.attrStr(' sum:' + res.GetOutput(), 'blue')

                # res.Clear()


        else:
            pcComment = ''
        if 'call' in mnemonicStr and inst.GetOperands(target).startswith('0x') and len(inst.GetOperands(target).split(',')) == 1:
            num = int(inst.GetOperands(target), 16)
            a = target.ResolveLoadAddress(num)
            pcComment = '; '
            if '__stubs' in a.section.name:
                pcComment += '(__TEXT.__stubs) '

            pcComment += a.symbol.name
            pcComment = ds.attrStr(pcComment, 'green')
            comments = ''


        match = re.search('(?<=\<\+)[0-9]+(?=\>)', inst.GetComment(target))
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


    if options.grep_functions:
        if grepSearch:
            return output
        else:
            return ''

    return output + '\n'


def generateDescriptionByAddress(addr, target):
    section = addr.section
    name = ''
    retDescription = ''
    loadAddr = hex(addr.GetLoadAddress(target))
    while section:
        name = '.' + section.name + name
        section = section.GetParent()

    # return name +'lkjlkj'
    if '__DATA.__objc_selrefs' in name:
        string = str(target.EvaluateExpression('*(char **)' + loadAddr))
        if len(string.split('"')) > 1:
            return (False, '"' + string.split('"')[1] + '"')
    elif '__DATA.__objc_classrefs' in name:
        idType = ds.getType('id')
        sbval = target.CreateValueFromAddress('hi', addr, idType)
        return (False, '(__DATA.__objc_classrefs) {}'.format(sbval.description))
    elif '__DATA.__cfstring' in name:
        charType = ds.getType('char*')
        newAddr = target.ResolveLoadAddress(addr.GetLoadAddress(target) + 0x10) # TODO, do 32 bit
        sbval = target.CreateValueFromAddress('hi', newAddr, charType)
        return (False, '(__DATA.__cfstring) {}'.format(sbval.summary))


    retDescription += name
    return (True, loadAddr + ' ' + str(addr.module.file.basename) + retDescription)


def generateBranchLines(branches, count, offsetSizeDict):
    lines = ['' for i in range(count)]
    multiplier = 1
    for branch in branches:
        inc = -1 if branch[0] > branch[1] else 1
        ceiling = offsetSizeDict[str(branch[1])]
        for i in range(branch[0], ceiling, inc):
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

    parser.add_option("-s", "--search_functions",
                  action="store",
                  default=None,
                  dest="search_functions",
                  help="Do a regex search for functions")

    parser.add_option("-g", "--grep_functions",
                  action="store",
                  default=None,
                  dest="grep_functions",
                  help="grep for comments in assembly, ideal w/ search_functions options")
    return parser
    

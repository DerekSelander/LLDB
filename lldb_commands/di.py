

import lldb
import os
import shlex
import optparse
import ds

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f di.handle_command di')

def handle_command(debugger, command, result, internal_dict):
    '''
    Wrapper (w/ color!) for LLDB's disassembly
    '''

    interp = debugger.GetCommandInterpreter() 
    res = lldb.SBCommandReturnObject()
    ()

    interp.HandleCommand('disassemble '+ str(command), res)
    if res.GetError() is None:
        result.SetError(str(res.GetError()))
        return

    output = res.GetOutput()
    finalOutput = ''
    for i, line in enumerate(output.split('\n')):
        if i == 0:
            w = line.split('`')
            if len(w) >= 2:
                finalOutput += ds.attrStr(w[0], 'cyan') + '`' + ds.attrStr(w[1], 'yellow') + '\n'
                continue

        w = [i for i in line.split(':') if i]
        if not len(w):
            continue

        if len(w) >= 2:
            address = ds.attrStr(w[0].ljust(22) + ':', 'grey')
        else:
            address = ''

        code = w[1].split(None, 1) # 'mov    r10, rcx ; lkjlkjlkj'.split(' ', 1)[1].split(',', 1)[1].split(';')

        mnemonic =  ds.attrStr(code[0].ljust(6), 'red') # mov

        if len(code) > 1 and len(code[1].split(';')) >= 2:
            k = code[1].split(';')
            comment = ds.attrStr('; ' + k[1].strip(), 'cyan')
        else:
            k = code[0].split(';')
            comment = ds.attrString('; ' + k[1].strip(), 'cyan') if len(k) > 1 else ''

        if len(code) == 1:
            opcodes = code[0].split(';')[0]
        else:
            opcodes = code[1].split(';')[0]

        ops = opcodes.split(',', 1)

        # # print('code: ' + str(code))
        # # print('opcodes '+ str(opcodes))
        # print(opcodes)
        if len(ops) == 1: # something like 'ret'
            op1 = ops[0]
            op2 = ''
        elif len(ops) == 2:
            op1 = ops[0]
            op2 = ops[1]
        else: 
            op1 = ''
            op2 = ''

        # op1 = ds.attrStr(op1
        # op1 = op1.ljust(6)
        op1 = op1 if op2 == '' else str(op1 + ',').ljust(6)
        op2 = ds.attrStr(op2, 'yellow')


        finalOutput += '{} {} {}{}{}\n'.format(address, mnemonic, op1, op2, comment)

    # Uncomment if you are expecting at least one argument
    # clean_command = shlex.split(args[0])[0]
    result.AppendMessage(finalOutput)

    
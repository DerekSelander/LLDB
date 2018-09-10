#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lldb
import re
import optparse
import ds 
import shlex

class GlobalOptions(object):
    symbols = {}

    @staticmethod
    def addSymbols(symbols, options, breakpoint):
        key = str(breakpoint.GetID())
        GlobalOptions.symbols[key] = (symbols, options)
        

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f breakifonfunc.breakifonfunc biof')

def breakifonfunc(debugger, command, exe_ctx, result, internal_dict):
    '''
    usage: biof [ModuleName] regex1 ||| [ModuleName2] regex2
    Regex breakpoint that stops only if the second regex breakpoint is in the stack trace
    For example, to only stop if code in the Test module resulted the setTintColor: being called
    biof setTintColor: ||| . Test 
    '''
    command_args = shlex.split(command, posix=False)
    parser = generateOptionParser()
    try:
        (options, args) = parser.parse_args(command_args)
    except e:
        result.SetError(e)
        return 

    # if len(args) >= 2:
    #     result.SetError(parser.usage)
    #     return 

    target = exe_ctx.target
    # if len(command.split('|||')) != 2:
    #     result.SetError(parser.usage)

    t = " ".join(args).split('|||')
    clean_command = t[0].strip().split()
    if len(clean_command) == 2:
        breakpoint = target.BreakpointCreateByRegex(clean_command[0], clean_command[1])
    else:
        breakpoint = target.BreakpointCreateByRegex(clean_command[0], None)

    moduleName = t[1].strip().split()[1]
    module = target.module[moduleName] 
    if not module:
        result.SetError('Invalid module {}'.format(moduleName))
        return

    searchQuery = t[1].strip().split()[0]
    s = [i for i in module.symbols if re.search(searchQuery, i.name)]

    GlobalOptions.addSymbols(s, options, breakpoint)
    breakpoint.SetScriptCallbackFunction("breakifonfunc.breakpointHandler")

    if not breakpoint.IsValid() or breakpoint.num_locations == 0:
        result.AppendWarning("Breakpoint isn't valid or hasn't found any hits: " + clean_command[0])
    else:
        result.AppendMessage("\"{}\" produced {} hits\nOnly will stop if the following stack frame symbols contain:\n{}` \"{}\" produced {} hits".format( 
             clean_command[0], breakpoint.num_locations, module.file.basename, searchQuery, len(s)) )


def breakpointHandler(frame, bp_loc, dict):
    if len(GlobalOptions.symbols) == 0:
        print("womp something internal called reload LLDB init which removed the global symbols")
        return True
    key = str(bp_loc.GetBreakpoint().GetID())
    searchSymbols = GlobalOptions.symbols[key][0]
    options = GlobalOptions.symbols[key][1]

    function_name = frame.GetFunctionName()
    thread = frame.thread
    if options.direct_call:
        frame = thread.frame[1]
        print(frame)
        symbol = frame.symbol
        return any([symbol in searchSymbols])


    s = [i.symbol for i in thread.frames]
    return any(x in s for x in searchSymbols)


def generateOptionParser():
    usage = breakifonfunc.__doc__
    parser = optparse.OptionParser(usage=usage, prog="biof")
    parser.add_option("-d", "--direct",
                  action="store_true",
                  default=False,
                  dest="direct_call",
                  help="Only stop if the second regex directly calls the breakpoint")
    return parser

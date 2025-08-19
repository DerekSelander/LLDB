# MIT License

# Copyright (c) 2021 Kazutoshi Miyasaka

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
import optparse
import shlex

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f cbd.handle_command cbd')

def handle_command(debugger, command, result, internal_dict):
    '''
    Disables a breakpoint currently stopped and continue process.
    '''
    command_args = shlex.split(command, posix=False)
    parser = generateOptionParser()

    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
    
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()

    count = thread.GetStopReasonDataCount()
    breakpoints = ""
    for i in range(0, count, 2):
        main = thread.GetStopReasonDataAtIndex(i)
        sub  = thread.GetStopReasonDataAtIndex(i + 1)       
        breakpoints = breakpoints + "{0}.{1} ".format(main, sub)

    if breakpoints.strip():
        delete_or_disable_string = "delete" if options.should_delete else "disable"
        exp = "break {0} {1}".format(delete_or_disable_string, breakpoints)
        
        res = lldb.SBCommandReturnObject()
        debugger.GetCommandInterpreter().HandleCommand(exp, res)
        if res.GetError():  
            result.SetError(res.GetError()) 
        print(exp)

    if not options.should_stay:
        debugger.SetAsync(True)
        process.Continue()

def generateOptionParser():
  usage = "Use 'cbd -h' for option desc"
  parser = optparse.OptionParser(usage=usage, prog='cbd') 
  parser.add_option("-d", "--delete", action="store_true", default=False, dest="should_delete", help="deleting breakpoint")
  parser.add_option("-s", "--stay", action="store_true", default=False, dest="should_stay", help="staying at the point after the excution")
  return parser

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
import shlex
import optparse


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f lookup.lookup lookup')


def lookup(debugger, command, result, internal_dict):
    '''
    A more attractive alternative to image lookup -rn. Performs a regular expression
    search on all modules loaded into the application. You can filter modules using the
    --module command

    Example:

    (lldb) lookup UIViewController.viewDid
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    clean_command = ('').join(args)
    target = debugger.GetSelectedTarget()
    if options.module: 
        module_name = options.module
        module = target.FindModule(lldb.SBFileSpec(module_name))
        if not module.IsValid():
            result.SetError(
                "Unable to open module name '{}', to see list of images use 'image list -b'".format(module_name))
            return


    module_dict = {}
    symbol_context_list = target.FindGlobalFunctions(clean_command, 0, lldb.eMatchTypeRegex)
    for symbol_context in symbol_context_list:
        key = symbol_context.module.file.basename
        if options.module and key != options.module:
            continue

        if not key in module_dict:
            module_dict[key] = []

        module_dict[key].append(symbol_context)

    return_string = generate_return_string(debugger, module_dict, options)
    result.AppendMessage(return_string)

def generate_return_string(debugger, module_dict, options):
    return_string = ''
    for key in module_dict:
        count = len(module_dict[key])
        tmp = module_dict[key][0]

        if options.module_summary:
            return_string += str(count) + ' hits in: ' + key + '\n'
            continue

        return_string += '****************************************************\n'
        return_string += str(count) + ' hits in: ' + key + '\n'
        return_string += '****************************************************\n'

        for symbol_context in module_dict[key]:
            if symbol_context.function.name is not None: 
                name = symbol_context.function.name
            elif symbol_context.symbol.name is not None: 
                name = symbol_context.symbol.name
            else:
                return_string += 'Can\'t find info for ' + str(symbol_context) + '\n\n'
                continue


            return_string += name
            if options.load_address:
                str_addr = str(hex(symbol_context.GetSymbol().GetStartAddress().GetLoadAddress(debugger.GetSelectedTarget())))
                end_addr = str(hex(symbol_context.GetSymbol().GetEndAddress().GetLoadAddress(debugger.GetSelectedTarget())))
                return_string += ', load_addr=[' + str_addr + '-' + end_addr + ']'

            return_string += '\n\n'


    return return_string


def generate_option_parser():
    usage = "usage: %prog [options] path/to/item"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-m", "--module",
                      action="store",
                      default=None,
                      dest="module",
                      help="Limit scope to a specific module")

    parser.add_option("-s", "--module_summary",
                      action="store_true",
                      default=False,
                      dest="module_summary",
                      help="Give the summary of return hits from the different modules")

    parser.add_option("-l", "--load_address",
                      action="store_true",
                      default=False,
                      dest="load_address",
                      help="Only print out the simple description with method name, don't print anything else")
    return parser

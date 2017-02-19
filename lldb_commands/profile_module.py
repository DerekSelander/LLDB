# MIT License
#
# Copyright (c) 2017 Derek Selander
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import lldb
import shlex
import optparse
import os
import textwrap
from stat import *


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f profile_module.profile_module pmodule')


def profile_module(debugger, command, result, internal_dict):
    '''Creates a custom dtrace script that profiles modules in an executable
    based upon its memory layout and ASLR. Provide no arguments w/ '-a' if 
    you want a count of all the modules firing. Provide a module if you want 
    to dump all the methods as they occur. 

    pmodule [[MODULENAME]...]

    You have the option to use objc or non-objc (i.e. objc$target or pid$target)
    Through the -n argument

    Examples:
    
    # Trace all Objective-C code in UIKit 
    (lldb) pmodule UIKit

    # Trace all non-Objective-C code in libsystem_kernel.dylib (i.e. pid$target:libsystem_kernel.dylib::entry)
    (lldb) pmodule -n libsystem_kernel.dylib

    # Dump errrything. Only displays count of function calls from modules after you end the script. Warning slow
    (lldb) pmodule -a
    '''

    command_args = shlex.split(command)
    parser = generate_option_parser()
    target = debugger.GetSelectedTarget()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError("option parsing failed")
        return
    pid = target.process.id

    # module_parirs = get_module_pair(, debugger)
    is_cplusplus = options.non_objectivec

    if not args and not options.all_modules:
        result.SetError('Need a module or use the -a option. You can list all modules by "image list -b"')
        return

    dtrace_script = generate_dtrace_script(debugger, options, args)

    filename = '/tmp/lldb_dtrace_pmodule'
    create_or_touch_filepath(filename, dtrace_script)

    copycommand = 'echo \"sudo {0}  -p {1}  2>/dev/null\" | pbcopy'
    os.system(copycommand.format(filename, pid))
    result.AppendMessage("Copied to clipboard. Paste in Terminal.")

    # 10.12.3 beta broke AppleScript's "do script" API. Dammit. Using pbcopy instead...
    # dtraceCommand = 'osascript -e \'tell application \"Terminal\" to activate & do script \"sudo {0}  -p {1}  \"\' 2>/dev/null'
    # os.system(dtraceCommand.format(filename, pid))
    # result.AppendMessage("Continuing in different Terminal tab...")
    
    result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)

def generate_conditional_for_module_name(module_name, debugger):
    pair = get_module_pair(module_name, debugger)
    template = '/ {} <= uregs[R_PC] && uregs[R_PC] <= {} /\n'
    return template.format(pair[0], pair[1])


def generate_dump_all_module_script(target):
    dtrace_script = r'''
    this->method_counter = \"Unknown\";
    program_counter = uregs[R_PC]; 
    '''
    dtrace_template = "this->method_counter = {} <= program_counter && program_counter <= {} ? \"{}\" : this->method_counter;\n"
    dtrace_template = textwrap.dedent(dtrace_template)

    for module in target.modules:
        section = module.FindSection("__TEXT")
        lower_bounds = section.GetLoadAddress(target)
        upper_bounds = lower_bounds + section.file_size
        module_name = module.file.basename
        if "_lldb_" not in module_name:
            dtrace_script += dtrace_template.format(lower_bounds, upper_bounds, module_name)

    return dtrace_script


def create_or_touch_filepath(filepath, dtrace_script):
    file = open(filepath, "w")
    file.write(dtrace_script)
    file.flush()
    st = os.stat(filepath)
    os.chmod(filepath, st.st_mode | S_IEXEC)
    file.close()

def generate_dtrace_script(debugger, options, args):
    target = debugger.GetSelectedTarget()
    is_cplusplus = options.non_objectivec
    dtrace_script = '''#!/usr/sbin/dtrace -s
#pragma D option quiet  

dtrace:::BEGIN
{{
    printf("Starting... Hit Ctrl-C to end. Observing {} functions in {}\\n");
}}
'''.format('non-Objective-C' if is_cplusplus else 'Objective-C', (', ').join(args))


    pid = target.process.id
    
    is_cplusplus = options.non_objectivec
    query_template = '{}$target:{}::entry\n'

    if options.all_modules:
        if is_cplusplus:
            dtrace_script += query_template.format('pid', '')
        else:
            dtrace_script += query_template.format('objc', '')

        dtrace_script += '{\n'
        dtrace_template = "this->method_counter = {} <= program_counter && program_counter <= {} ? \"{}\" : this->method_counter;\n"
        dtrace_template = textwrap.dedent(dtrace_template)

        for module in target.modules:
            section = module.FindSection("__TEXT")
            lower_bounds = section.GetLoadAddress(target)
            upper_bounds = lower_bounds + section.file_size
            module_name = module.file.basename
            if "_lldb_" not in module_name:
                dtrace_script += dtrace_template.format(lower_bounds, upper_bounds, module_name)
        dtrace_script += "\n@num[this->method_counter] = count();\n}\n"

    else:
        for module_name in args:

            # Objective-C logic:        objc$target:::entry / {} <= uregs[R_PC] && uregs[R_PC] <= {} / { }
            if not is_cplusplus:
                dtrace_script += query_template.format('objc', '')
                dtrace_script += generate_conditional_for_module_name(module_name, debugger)

            # Non-Objective-C logic:    pid$target:Module::entry { }
            if is_cplusplus:
                dtrace_script += query_template.format('pid', module_name)
                dtrace_script += '{\n    printf("[%s] %s\\n", probemod, probefunc);\n'
            else:
                dtrace_script += '{\n    printf("0x%012p %c[%s %s]\\n", uregs[R_RDI], probefunc[0], probemod, (string)&probefunc[1]);\n'

            # Logic to append counting at the termination of script
            if options.count:
                dtrace_script += '    @numWrites{}[probefunc] = count();\n'.format(module_name)

            dtrace_script += '}\n'

    return dtrace_script


def get_module_pair(module_name, debugger):
    target = debugger.GetSelectedTarget()

    module = target.FindModule(lldb.SBFileSpec(module_name))
    if not module.file.exists:
        result.SetError(
            "Unable to open module name '{}', to see list of images use 'image list -b'".format(module_name))
        return

    section = module.FindSection("__TEXT")
    lower_bounds = section.GetLoadAddress(target)
    upper_bounds = lower_bounds + section.file_size
    return (lower_bounds, upper_bounds)


def generate_option_parser():
    usage = "usage: %prog [options] arg1 [arg2...]"
    parser = optparse.OptionParser(usage=usage, prog='pmodule')
    parser.add_option("-n", "--non_objectivec",
                      action="store_true",
                      default=False,
                      dest="non_objectivec",
                      help="Use Objective-C instead of using target")

    parser.add_option("-c", "--count",
                      action="store_true",
                      default=False,
                      dest="count",
                      help="Count method calls for framework")

    parser.add_option("-a", "--all_modules",
                      action="store_true",
                      default=False,
                      dest="all_modules",
                      help="Profile all modules. If this is selected, specific modules are ignored and counts are returned when scrit finishes")
    return parser

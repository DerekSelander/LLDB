

import lldb
import os
import shlex
import optparse
import textwrap
import time
from stat import *

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f include.handle_command include -h "imports a "self-contained" C header"')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Documentation for how to use include goes here 
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    if len(args) != 1:
        result.SetError("expects fullpath to C header")
        return  

    header = args[0]
    if not (os.path.exists(header) or os.path.isfile(header)):
        result.SetError("input needs to be a C file")
        return  

    dbgname = debugger.GetInstanceName()
    filename_path = '/tmp/lldb_user_modules/'
    filename = "module" + str(time.time()).replace('.', '')

    strlist = debugger.GetInternalVariableValue('target.clang-module-search-paths', dbgname)
    if strlist.GetSize() == 0 or not '/tmp/lldb_user_modules' in strlist.GetStringAtIndex(0):
        debugger.SetInternalVariable('target.clang-module-search-paths', filename_path, dbgname)


    if not os.path.exists(filename_path):
        os.makedirs(filename_path)

    modulemap = generate_modulemap(filename, os.path.abspath(header))
    create_or_touch_filepath(filename_path + "module.map", modulemap, options.clean)


    # Uncomment if you are expecting at least one argument
    # clean_command = shlex.split(args[0])[0]
    result.AppendMessage("{} -> module \"{}\"".format(header, filename))
    debugger.HandleCommand('exp -lobjc -O -- @import ' + filename )


def generate_modulemap(filename, filepath):
    modulemap = '''module {0} {{
  header "{1}"
}}

'''.format(filename, filepath)

    return modulemap 

def create_or_touch_filepath(filepath, modulemap_contents, should_wipe):
    if should_wipe:
        os.remove(filepath)
    file = open(filepath, "a+")
    file.write(modulemap_contents)
    file.flush()
    st = os.stat(filepath)
    os.chmod(filepath, st.st_mode | S_IEXEC)
    file.close()

def generate_option_parser():
    usage = "usage: %prog [options] fullpath to C header"
    parser = optparse.OptionParser(usage=usage, prog="include")

    parser.add_option("-c", "--clean",
                      action="store_true",
                      default=False,
                      dest="clean",
                      help="This will wipe the module.map file so you can start fresh")
    return parser
    
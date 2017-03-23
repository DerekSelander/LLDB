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
import optparse
import shlex
from stat import *

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f generate_new_script.generate_new_script __generate_script')


def generate_new_script(debugger, command, result, internal_dict):
    '''
    Generates a new script in the same directory as this file.
    Can generate function styled scripts or class styled scripts.

    Expected Usage: 
    __generate_script cool_command
    reload_lldbinit
    cool_command
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    if not args:
        result.SetError('Expects a filename. Usage: __generate_script filename')
        return

    clean_command = ('').join(args)
    file_path = str(os.path.splitext(os.path.join( os.path.dirname(__file__), clean_command))[0] + '.py')
    if os.path.isfile(file_path):
        result.SetError('There already exists a file named "{}", please remove the file at "{}" first'.format(clean_command, file_path))
        return

    if options.create_class:
        script = generate_class_file(clean_command, options)
    else:
        script = generate_function_file(clean_command, options)
    create_or_touch_filepath(file_path, script)
    os.system('open -R ' + file_path)
    result.AppendMessage('Opening \"{}\"...'.format(file_path))


def generate_class_file(filename, options):
    resolved_name = options.command_name if options.command_name else filename
    script = r'''

import lldb
import os
import shlex
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('''

    script +=  "'command script add -c " + filename + ".LLDBCustomCommand " + resolved_name + "')"
    script += r'''

class LLDBCustomCommand:

    def __init__(self, debugger, session_dict):
        # This is where you setup properties for the class
        pass

    def __call__(self, debugger, command, exe_ctx, result): 
        # This is where you handle the command

        command_args = shlex.split(command, posix=False)

        parser = self.generate_option_parser()
        try:
            (options, args) = parser.parse_args(command_args)
        except:
            result.SetError(parser.usage)
            return

        # Uncomment if you are expecting at least one argument
        # clean_command = shlex.split(args[0])[0]
        result.AppendMessage('Hello! the ''' + resolved_name + r''' command is working!')


    def generate_option_parser(self):
        usage = "usage: %prog [options] path/to/item"
        parser = optparse.OptionParser(usage=usage, prog="''' + resolved_name + r'''")
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

    def get_short_help(self): 
        return 'Short help goes here'

    def get_long_help(self): 
        return '''
    script += "'''\n        Your long help goes here\n        '''"

    return script

def generate_function_file(filename, options):
    resolved_name = options.command_name if options.command_name else filename
    script = r'''

import lldb
import os
import shlex
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    '''
    script += '\'command script add -f {}.handle_command {}\')'.format(filename, resolved_name)
    script += r'''

def handle_command(debugger, command, result, internal_dict):
    ''' 
    script += "\'\'\'\n    Documentation for how to use " + resolved_name + " goes here \n    \'\'\'"
    
    script += r'''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    # Uncomment if you are expecting at least one argument
    # clean_command = shlex.split(args[0])[0]
    '''

    script += "result.AppendMessage('Hello! the " + resolved_name + " command is working!')"
    script += r'''


def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="''' + resolved_name + r'''")
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
    '''
    return script

def create_or_touch_filepath(filepath, script):
    file = open(filepath, "w")
    file.write(script)
    file.flush()
    st = os.stat(filepath)
    os.chmod(filepath, st.st_mode | S_IEXEC)
    file.close()

def generate_option_parser():
    usage = "usage: %prog [options] nameofscript"
    parser = optparse.OptionParser(usage=usage, prog="__generate_script")

    parser.add_option("-n", "--command_name",
                      action="store",
                      default=None,
                      dest="command_name",
                      help="By default, the script will use filename for the LLDB command. This will override the command name to a name of your choosing")

    parser.add_option("-c", "--create_class",
                      action="store_true",
                      default=False,
                      dest="create_class",
                      help="By default, this script creates a function. This will use a class instead")
    return parser

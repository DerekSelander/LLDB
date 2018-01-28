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
        'command script add -f yoink.yoink yoink -h "Copies contents of remote contents to local computer"')


def yoink(debugger, command, exe_ctx, result, internal_dict):
    '''
    Takes a path on a iOS/tvOS/watchOS and writes to the /tmp/ dir on your computer.
    If it can be read by -[NSData dataWithContentsOfFile:], it can be written to disk

    Example (on iOS 10 device): 

    yoink /System/Library/Messages/iMessageEffects/CKConfettiEffect.bundle/CKConfettiEffect
    '''

    command_args = shlex.split(command)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    clean_command = ('').join(args)
    command_script = '''expression -lobjc -O -- @import Foundation; id data = [NSData dataWithContentsOfFile:@\"{}\"];
[NSString stringWithFormat:@\"%p,%p,%p\", data, (uintptr_t)[data bytes], (uintptr_t)[data length] + (uintptr_t)[data bytes]]'''.format(clean_command)
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    interpreter.HandleCommand(command_script, res)
    if not res.HasResult():
        result.SetError('There\'s no result')
        return

    response = res.GetOutput().split(',')

    if len(response) is not 3:
        result.SetError('Bad Fromatting')
        return

    if int(response[0], 16) is 0:
        result.SetError('Couldn\'t open file {}'.format(clean_command))
        return

    basename = os.path.basename(clean_command)
    debugger.HandleCommand(
        'memory read {} {} -r -b -o /tmp/{}'.format(response[1], response[2], basename))

    interpreter.HandleCommand('po [{} dealloc]'.format(response[0]), res)

    fullpath = '/tmp/{}'.format(basename)

    if options.open_immediately:
        print('Opening file...')
        os.system('open \"{}\"'.format(fullpath))
    else:
        os.system('open -R ' + fullpath)
        print('Opening \"{}\"...'.format(fullpath))

def generate_option_parser():
    usage = "usage: %prog [options] path/to/item"
    parser = optparse.OptionParser(usage=usage, prog="yoink")
    parser.add_option("-o", "--open_immediately",
                      action="store_true",
                      default=False,
                      dest="open_immediately",
                      help="Opens the copied item immediately using the default 'open' cmd, useful for pics")

    parser.add_option("-c", "--copy_file_path",
                      action="store_true",
                      default=False,
                      dest="copy_file_path",
                      help="Copies the file path to the clipboard")

    return parser

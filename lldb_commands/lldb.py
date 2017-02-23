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
import json


def __lldb_init_module(debugger, internal_dict):
    load_python_scripts_in_this_dir(debugger, True)
    load_python_scripts_in_this_dir(debugger, False)

def load_python_scripts_in_this_dir(debugger, is_scripts):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    file_path = os.path.realpath(__file__)
    dir_name = os.path.dirname(file_path)
    this_files_basename = os.path.basename(__file__)
    filetype = '.py' if is_scripts else '.txt'
    cmd = 'command script import ' if is_scripts else 'command source -s1 '
    for file in os.listdir(dir_name):
        if file.endswith(filetype) and file != this_files_basename:
            fullpath = dir_name + '/' + file
            interpreter.HandleCommand(cmd + fullpath, res)
            if res.GetError():
                print ('***************************************\nError in' + fullpath + '\n' + res.GetError())
                return



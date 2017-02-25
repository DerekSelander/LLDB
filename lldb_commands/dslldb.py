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

def __lldb_init_module(debugger, internal_dict):
    file_path = os.path.realpath(__file__)
    dir_name = os.path.dirname(file_path)
    load_python_scripts_dir(dir_name)

def load_python_scripts_dir(dir_name):
    this_files_basename = os.path.basename(__file__)
    cmd = ''
    for file in os.listdir(dir_name):
        if file.endswith('.py'):
            cmd = 'command script import ' 
        elif file.endswith('.txt'):
            cmd = 'command source  '
        else: 
            continue

        if file != this_files_basename:
            fullpath = dir_name + '/' + file
            moduleName = os.path.splitext(file)[0]
            print(fullpath)
            lldb.debugger.HandleCommand(cmd + fullpath)

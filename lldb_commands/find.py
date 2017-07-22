

import lldb
import ds
import os
import shlex
import re
import subprocess
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f find.handle_command find')

def handle_command(debugger, command, result, internal_dict):
    '''
    Documentation for how to use find goes here 
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    try:
        addr = int(command, 16)
    except:
        addr = int(command)

    target = ds.getTarget()
    module = target.ResolveLoadAddress(addr).module
    executablePath = module.file.fullpath
    pagesize = ds.getSection(name="__PAGEZERO").size
    loadOffset = ds.getSection(module=executablePath, name="__TEXT").addr.GetLoadAddress(target) - pagesize
    searchAddr = addr - loadOffset 

    command = '/usr/bin/otool -tv ' + executablePath
    output = subprocess.Popen(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True).communicate()[0]
    matches = re.findall(".*rip.*\n\w+", output)
    regex = re.compile('(?P<initial>\w+)?\t\w+\w.*(?P<offset>\-?0x\w+).*\n(?P<addr>\w+)')

    outputStr = ''
    for i, m in enumerate(matches):
        res = regex.match(m)
        if not res:
            continue
        address = int(res.group('addr'), 16)
        offset = int(res.group('offset'), 16)

        potential = address + offset
        if searchAddr == potential:

            if res.group('initial'):
                resolved = int(result.group('initial'), 16) + loadOffset 
            else: 
                resolved = int(regex.match(matches[i - 1]).group('addr'), 16) + loadOffset

            outputStr += 'one hit at {}\n'.format(resolved)
            # print("match at {}".format(hex(resolved)))


    result.AppendMessage(outputStr)

def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="find")
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
    
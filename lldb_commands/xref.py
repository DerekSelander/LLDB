

import lldb
import ds
import os
import shlex
import re
import subprocess
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f xref.handle_command xref')

def handle_command(debugger, command, result, internal_dict):
    '''
    Documentation for how to use xref goes here 
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    try:
        addr = int(args[0], 16)
    except:
        addr = int(args[0])

    target = ds.getTarget()
    sbaddress = target.ResolveLoadAddress(addr)
    if len(args) == 2:
        module = target.module[args[1]]
    else:
        module = sbaddress.module
    section = sbaddress.section

    resolvedAddresses = []
    outputStr = ''

    if section.name == '__cstring':
        outputStr += getCFAddress(sbaddress)
    if section.name == '__objc_methname':
        outputStr += getObjcMethNameAddress(sbaddress)

    executablePath = module.file.fullpath
    pagesize = ds.getSection(name="__PAGEZERO").size
    loadOffset = ds.getSection(module=executablePath, name="__TEXT").addr.GetLoadAddress(target) - pagesize
    searchAddr = addr - loadOffset 

    command = '/usr/bin/otool -tv ' + executablePath
    output = subprocess.Popen(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True).communicate()[0]
    matches = re.findall(".*rip.*\n\w+", output)
    regex = re.compile('(?P<initial>\w+)?\t\w+\w.*[^\*](?P<offset>\-?0x\w+).*\n(?P<addr>\w+)')

    for i, m in enumerate(matches):
        res = regex.match(m)
        if not res or not res.group('addr') or not res.group('offset'):
            continue
        # result.AppendMessage(m)
        # result.AppendMessage(res.group('addr') + '\n')
        try:
            address = int(res.group('addr'), 16)
            offset = int(res.group('offset'), 16)
        except:
            outputStr += 'error: at {} {}'.format(res.group('addr'), res.group('offset'))
            continue

        potential = address + offset
        if searchAddr == potential:

            if res.group('initial'):
                resolved = int(res.group('initial'), 16) + loadOffset 
            else: 
                resolved = int(regex.match(matches[i - 1]).group('addr'), 16) + loadOffset


            a = target.ResolveLoadAddress(resolved)
            resolvedAddresses.append(a)
            
        # print("match at {}".format(hex(resolved)))

    outputStr += generateAddressInfo(resolvedAddresses, options)
    result.AppendMessage(outputStr)

def getObjcMethNameAddress(addr):
    outputStr = ''
    section = addr.section
    target = ds.getTarget()
    fileAddr = addr.file_addr
    executablePath = addr.module.file.fullpath
    dataSection = ds.getSection(module=executablePath, name='__DATA.__objc_selrefs')
    charPointerType = target.GetBasicType(lldb.eBasicTypeChar).GetPointerType()

    dataArray = dataSection.data.uint64s # TODO implement 32 bit
    for i, x in enumerate(dataArray):
            if x != fileAddr:
                continue
            offset = i  * 8 # TODO implement 32 bit
            loadAddress = dataSection.addr.GetLoadAddress(target) + offset
            startAddr = target.ResolveLoadAddress(loadAddress)
            straddr = target.ResolveLoadAddress(dataSection.addr.GetLoadAddress(target) + (i * 8))
            summary = target.CreateValueFromAddress('somename', straddr, charPointerType).summary
            outputStr += '[{}] {}\n'.format(hex(startAddr.GetLoadAddress(target)), summary)
    return outputStr




def getCFAddress(addr):
    outputStr = ''
    section = addr.section
    target = ds.getTarget()
    fileAddr = addr.file_addr
    executablePath = addr.module.file.fullpath
    dataSection = ds.getSection(module=executablePath, name='__DATA.__cfstring')
    if dataSection is None:
        return ''
    size = dataSection.size
    charPointerType = target.GetBasicType(lldb.eBasicTypeChar).GetPointerType()
    dataArray = dataSection.data.uint64s # TODO implement 32 bit
    for i, x in enumerate(dataArray):
        if i % 4 != 2:
            continue

        if x == fileAddr:
            offset = (i - 2) * 8 # TODO implement 32 bit
            # size = dataArray[i + 1]
            # lldb.SBData
            loadAddress = dataSection.addr.GetLoadAddress(target) + offset
            startAddr = target.ResolveLoadAddress(loadAddress)
            straddr = target.ResolveLoadAddress(dataSection.addr.GetLoadAddress(target) + (i * 8))
            summary = target.CreateValueFromAddress('somename', straddr, charPointerType).summary
            outputStr += '[{}] {}\n'.format(hex(startAddr.GetLoadAddress(target)), summary)
    return outputStr

def generateAddressInfo(addresses, options):
    target = ds.getTarget()
    outputStr = ''
    for a in addresses:
        symbol = a.symbol
        if symbol:
            symbolOffset = a.GetLoadAddress(target) - symbol.addr.GetLoadAddress(target)
            symbolAddress = hex(symbol.addr.GetLoadAddress(target))
            outputStr += '[{}] {} + {}\n\n'.format(ds.attrStr(symbolAddress, 'yellow'), ds.attrStr(symbol.name, 'cyan'), symbolOffset)
        else:
            outputStr +'error: '
    return outputStr

def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="find")
    # parser.add_option("-m", "--module",
    #                   action="store",
    #                   default=None,
    #                   dest="module",
    #                   help="This is a placeholder option to show you how to use options with strings")
    # parser.add_option("-c", "--check_if_true",
    #                   action="store_true",
    #                   default=False,
    #                   dest="store_true",
    #                   help="This is a placeholder option to show you how to use options with bools")
    return parser
    
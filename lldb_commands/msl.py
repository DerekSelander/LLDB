

import lldb
import os
import shlex
import optparse
import sbt

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f msl.handle_command msl')
    debugger.HandleCommand('command alias enable_logging expression -lobjc -O -- extern void turn_on_stack_logging(int); turn_on_stack_logging(1);')


def handle_command(debugger, command, result, internal_dict):
    '''
    Documentation for how to use msl goes here 
    '''

    command_args = shlex.split(command)
    parser = generateOptionParser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    cleanCommand = args[0]
    frame = debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
    target = debugger.GetSelectedTarget()
    script = generateScript(cleanCommand, options)
    sbval = frame.EvaluateExpression(script, generateOptions())

    if sbval.error.fail: 
        result.AppendMessage(str(sbval.error))
        return

    val = lldb.value(sbval)
    addresses = []
    for i in range(val.count.sbvalue.unsigned):
        address = val.addresses[i].sbvalue.unsigned
        loadAddr = target.ResolveLoadAddress(address).GetLoadAddress(target)
        addresses.append(loadAddr)
        # stackString = str(target.ResolveLoadAddress(address).symbol)
        # result.AppendMessage(stackString)

    if options.resymbolicate:
        retString = sbt.processStackTraceStringFromAddresses(addresses, target)
    else:
        retString = processStackTraceStringFromAddresses(addresses, target)

    frame.EvaluateExpression('free(' + str(val.addresses.sbvalue.unsigned) + ')', generateOptions())
    result.AppendMessage(retString)


def processStackTraceStringFromAddresses(frameAddresses, target):

    frame_string = ''
    for index, frameAddr in enumerate(frameAddresses):
        addr = target.ResolveLoadAddress(frameAddr)
        symbol = addr.symbol
        name = symbol.name
        offset_str = ''
        offset = addr.GetLoadAddress(target) - addr.symbol.addr.GetLoadAddress(target)
        if offset > 0:
            offset_str = '+ {}'.format(offset)

        frame_string += 'frame #{:<2}: {} {}`{} {}\n'.format(index, hex(addr.GetLoadAddress(target)), addr.module.file.basename, name, offset_str)

    return frame_string

def generateOptions():
    expr_options = lldb.SBExpressionOptions()
    expr_options.SetUnwindOnError(True)
    expr_options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    expr_options.SetCoerceResultToId(True)
    expr_options.SetGenerateDebugInfo(True)
    return expr_options

def generateScript(addr, options):
  script = '  mach_vm_address_t addr = (mach_vm_address_t)' + str(addr) + ';\n'
  script += r'''
typedef struct $LLDBStackAddress {
    mach_vm_address_t *addresses;
    uint32_t count = 0;
} $LLDBStackAddress;

  $LLDBStackAddress stackaddress;
  mach_vm_address_t address = (mach_vm_address_t)addr;
  void * task = mach_task_self_;
  stackaddress.addresses = (mach_vm_address_t *)calloc(100, sizeof(mach_vm_address_t));
  __mach_stack_logging_get_frames(task, address, stackaddress.addresses, 100, &stackaddress.count);
  stackaddress
  '''
  return script

def generateOptionParser():
    usage = "usage: %prog [options] 0xaddrE55"
    parser = optparse.OptionParser(usage=usage, prog="msl")
    parser.add_option("-r", "--resymbolicate",
                      action="store_true",
                      default=False,
                      dest="resymbolicate",
                      help="Resymbolicate Stripped out Objective-C code")
    return parser
    
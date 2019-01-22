

import lldb
import os
import shlex
import optparse
import ds

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f info.handle_command info -h "Get info about an address in memory"')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Documentation for how to use info goes here 
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    target = debugger.GetSelectedTarget()

    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return


    if len(args) != 1:
        result.SetError("Expects an address")
        return        

    try:
        if args[0].startswith("0x") or args[0].startswith("0X"):
            address = int(args[0], 16)
        else:
            address = int(args[0], 10)

    except ValueError:
        frame = target.GetProcess().GetSelectedThread().GetSelectedFrame()
        val = frame.var(args[0])
        if val.IsValid() == False:
            result.SetError("can't parse \"{}\"".format(args[0]))
            return
        address = val.unsigned

    addr = target.ResolveLoadAddress(address)
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()


    returnDescription = ""
    foundAddress = False

    if addr.GetSection().IsValid():
        foundAddress, returnDescription = tryMachOAddress(addr, target, options)

    if foundAddress == False:
        foundAddress, returnDescription = tryHeapAddress(addr, target, options)


    if foundAddress:
        result.AppendMessage('{}'.format(returnDescription))
    else:
        debugger.HandleCommand("image lookup -v -a {}".format(addr))
        # result.SetError('Couldn\'t find info for address \'{}\''.format(addr))

    

def tryMachOAddress(addr, target, options):

    returnDescription = ""
    section = addr.GetSection()
    if not section.IsValid():
        return False, ""

    sectionName = section.GetName()
    tmpS = section 
    while tmpS.GetParent().IsValid():
        tmpS = tmpS.GetParent()
        sectionName = "{}.{}".format(tmpS.GetName(), sectionName)

    module = addr.GetModule()
    if module.IsValid():
        sectionName = " `{}`{}".format(ds.attrStr(addr.GetModule().GetFileSpec().GetFilename(), 'cyan'), ds.attrStr(sectionName, 'yellow'))

    addrOffset = addr.GetLoadAddress(target) - section.GetLoadAddress(target)
    sectionName += " + {}".format(hex(addrOffset))



    symbol = addr.GetSymbol()
    #  Is it a known function?
    if symbol.IsValid():
        returnDescription += "  {}    ".format(ds.attrStr(symbol.GetName(), 'yellow'))
        startAddr = symbol.GetStartAddress()

        # Symbol address offset, if any
        addrOffset = addr.GetLoadAddress(target) - startAddr.GetLoadAddress(target)
        returnDescription += " <+{}>".format(addrOffset)

        # Mangled function
        if options.verbose:
            if symbol.GetMangledName():
                returnDescription += ", ({})".format(symbol.GetMangledName())

            returnDescription += ", External: {}".format("YES" if symbol.IsSynthetic() else "NO")

    tpe = target.GetBasicType(lldb.eBasicTypeNullPtr).GetPointerType()
    # val = target.EvaluateExpression("(void *){}".format(addr.GetLoadAddress(target)), ds.genExpressionOptions())
    # if val.IsValid():
    #     data = val.GetData()
    #     k = ds.formatFromData(data, section, 1)
        # returnDescription += '{}'.format(k[1])


    returnDescription += sectionName
    return True, returnDescription



def tryHeapAddress(addr, target, options):
    returnDescription = ""
    cleanCommand = 'const void * ptr = (const void *){};'.format(addr.GetLoadAddress(target))
    cleanCommand += 'BOOL verboseMode = {};'.format("YES" if options.verbose else "NO")
    cleanCommand += r'''


@import Foundation;


    
    

    NSMutableString *retString;
    if ((void*)malloc_zone_from_ptr(ptr)) {

      retString = (NSMutableString*)[[NSMutableString alloc] initWithFormat:@"%p heap pointer, %s, (0x%x bytes)", ptr, (char *)malloc_get_zone_name((malloc_zone_t*)malloc_zone_from_ptr(ptr)), (size_t)malloc_good_size((size_t)malloc_size(ptr))];
    }
    
    retString ? retString : nil;
    '''

    val = target.EvaluateExpression(cleanCommand, ds.genExpressionOptions())
    if val.GetValueAsUnsigned() == 0:
        return False, ""

    returnDescription += val.description
    return True, returnDescription



def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="info")
    parser.add_option("-v", "--verbose",
                      action="store_true",
                      default=None,
                      dest="verbose",
                      help="Use verbose amount of info")
    return parser
    
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
import ds
import shlex
import re
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f lookup.lookup lookup -h "lookup functions or variables"')


def lookup(debugger, command, exe_ctx, result, internal_dict):
    '''
    Perform a regular expression search for stuff in an executable

    # Find all methods that contain the phrase viewDidLoad
    (lldb) lookup viewDidLoad
    
    # Find a summary of all the modules that have a (known) function containing the phrase viewDidLoad
    (lldb) lookup viewDidLoad -s
    
    # Search for Objective-C code in a stripped module (i.e. in SpringBoard)
    (lldb) loo -x StocksFramework .
    
    # Search for Objective-C code containing the case insensitive phrase init inside a stripped main bundle
    (lldb) lookup -X (?i)init
    
    # Search for all hardcoded, embeded `char *` inside an executable containing the phrase *http* inside UIKit
    (lldb) lookup -S http -m UIKit
    
    # Dump all the md5'd keys in libMobileGestalt along w/ the address in memory
    (lldb) loo -S ^[a-zA-Z0-9\+]{22,22}$ -m libMobileGestalt.dylib -l
    
    # Dump all the global bss code referenced by DWARF. Ideal for accessing `static` variables when not in scope
    (lldb) lookup . -g HonoluluArt -l
    '''
    if not ds.isProcStopped():
        result.SetError(ds.attrStr('You must have the process suspended in order to execute this command', 'red'))
        return

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    clean_command = ('').join(args)
    target = exe_ctx.target
    frame = exe_ctx.frame
    if options.stripped_executable is not None or options.stripped_executable_main:
        expr_options = lldb.SBExpressionOptions()
        expr_options.SetIgnoreBreakpoints(False);
        expr_options.SetFetchDynamicValue(lldb.eDynamicCanRunTarget);
        expr_options.SetTimeoutInMicroSeconds (30*1000*1000) # 30 second timeout
        expr_options.SetTryAllThreads (True)
        expr_options.SetUnwindOnError(False)
        expr_options.SetGenerateDebugInfo(True)
        expr_options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
        expr_options.SetCoerceResultToId(True)
        if frame is None:
            result.SetError('You must have the process suspended in order to execute this command')
            return

        if options.stripped_executable:
            module_name = options.stripped_executable

            module = target.module[module_name]

            if module is None:
                result.SetError('Couldn\'t find the module, "', module_name + '"')
                return

            command_script = generate_main_executable_class_address_script(module.file.dirname, options)
        else:
            command_script = generate_main_executable_class_address_script(None, options)
        # debugger.HandleCommand('expression -g -lobjc -O -- ' + command_script)
        # return 

        expr_value = frame.EvaluateExpression (command_script, expr_options)
        output_description = str(expr_value.GetObjectDescription())
            
        # result.AppendMessage(output_description)
        # print(output_description.split())
        output = '\n\n'.join([line for line in output_description.split('\n') if re.search(clean_command, line)])

        if options.create_breakpoint:
            m = re.findall('0x[a-fA-F0-9]+', output)
            result.AppendMessage(ds.attrStr("Creating breakpoints on all returned functions", 'red'))
            for k in m:
                hexAddr = int(k, 16)
                target.BreakpointCreateByAddress(hexAddr)

        if not ds.isXcode():
            output = re.sub('0x[a-fA-F0-9]+', '\x1b\x5b33m\g<0>\x1b\x5b39m', output)
            output = re.sub('[\-|\+].*', '\033[36m\g<0>\033[0m', output)
        result.AppendMessage(output)
        return

    if options.strings:
        output = generate_cstring_dict(target, args[0], options)
        result.AppendMessage(output)
        return


    if options.module:
        module_name = options.module
        module = target.FindModule(lldb.SBFileSpec(module_name))
        if not module.IsValid():
            result.SetError(
                "Unable to open module name '{}', to see list of images use 'image list -b'".format(module_name))
            return


    module_dict = {}

    if options.global_var or options.global_var_noeval:
        module_name = options.global_var if options.global_var else options.global_var_noeval
        module = target.FindModule(lldb.SBFileSpec(module_name))
        if not module.IsValid():
            result.SetError(
                "Unable to open module name '{}', to see list of images use 'image list -b'".format(module_name))
            return
        symbol_context_list = [i for i in module.get_symbols_array() if i.GetType() == lldb.eSymbolTypeData and i.addr.IsValid() and i.IsValid()]

    else:
        symbol_context_list = target.FindGlobalFunctions(clean_command, 0, lldb.eMatchTypeRegex)

    for symbol_context in symbol_context_list:
        if options.global_var is not None or options.global_var_noeval is not None:
            key = symbol_context.addr.module.file.basename
        else:
            key = symbol_context.module.file.basename

        if options.module and key != options.module:
            continue

        if not key in module_dict:
            module_dict[key] = []


        if options.global_var or options.global_var_noeval:
            if re.search(clean_command, symbol_context.name):
                module_dict[key].append(symbol_context.addr.GetSymbolContext(lldb.eSymbolContextEverything))
        else:
            module_dict[key].append(symbol_context)

    return_string = generate_return_string(target, frame, module_dict, options)
    result.AppendMessage(return_string)

def generate_cstring_dict(target, command, options):

    if options.module:
        module_name = options.module
        module = target.FindModule(lldb.SBFileSpec(module_name))
        if not module.IsValid():
            result.SetError(
                "Unable to open module name '{}', to see list of images use 'image list -b'".format(module_name))
            return
        modules = [module]
    else:
        modules = target.modules

    return_string = ''
    error = lldb.SBError()
    prog = re.compile(command)
    for m in modules: 
        section = ds.getSection(m, '__TEXT.__cstring')
        if section is None:
            continue

        data = section.data
        dataArray = section.data.sint8s
        sectionAddress = section.addr.GetLoadAddress(target)

        moduleString = ''
        indices = [i for i, x in enumerate(dataArray) if x > 1 and dataArray[i-1] == 0 and x != 0]
        returnDict = {}
        for i in indices:
            cString = data.GetString(error, i)
            if prog.search(cString):
                returnDict[hex(sectionAddress + i)] = cString

        if len(returnDict) == 0:
            continue

        if options.module_summary:
            return_string += '{} hits in: {}\n'.format(str(len(returnDict)), m.file.basename)
        else:
            moduleString = '\n' + ds.attrStr('****************************************************', 'cyan') + '\n{} hits in: {}'.format(str(len(returnDict)), ds.attrStr(m.file.basename, 'red')) + '\n' + ds.attrStr('****************************************************', 'cyan') + '\n'

            
            for k, v in returnDict.items():
                if options.load_address:
                    moduleString +=  ds.attrStr('[' + k + ']', 'yellow') + ' '
                moduleString += ds.attrStr(v, 'cyan') + '\n'

        return_string += moduleString

    return return_string

def generate_return_string(target, frame, module_dict, options):
    return_string = ''
    shouldGetSummary = True if (len(module_dict) < 32) else False 
    for key in module_dict:
        count = len(module_dict[key])
        if len(module_dict[key]) == 0:
            continue
        tmp = module_dict[key][0]

        if options.module_summary:
            return_string += str(count) + ' hits in: ' + key + '\n'
            continue

        return_string += ds.attrStr('****************************************************', 'cyan') + '\n'
        return_string += str(count) + ' hits in: ' + ds.attrStr(key, 'red') + '\n'
        return_string += ds.attrStr('****************************************************', 'cyan') + '\n'
        module = target.module[key]
        for symbol_context in module_dict[key]:
            if options.global_var or options.global_var_noeval:
                name = symbol_context.symbol.name
                if options.global_var:
                    addr = hex(symbol_context.symbol.addr.GetLoadAddress(target))
                    if shouldGetSummary:
                        val = module.FindFirstGlobalVariable(target, name)
                        if not val:
                            # TODO get variable size 
                            val = frame.EvaluateExpression('*(void**)' + addr)
                        
                        descp = val.description

                        if val.summary:
                            name += '\n' + val.summary
                        elif descp and descp != '<object returned empty description>' and descp != '<nil>':
                            name += '\n' + descp
                        else:
                            name += '\n' + ('0x%010x' % val.unsigned)
                    else:
                        # TODO get variable size 
                        val = frame.EvaluateExpression('*(void**)' + addr)
                        name += '\n' + (val.description if val.description else '0x%010x' % val.unsigned)

            elif symbol_context.function.name is not None:
                name = symbol_context.function.name
                if options.mangled_name:
                    mangledName = symbol_context.symbol.GetMangledName()
                    name += ', ' + mangledName if mangledName else '[NONE]'

                if options.source_info:
                    lineEntry = symbol_context.GetSymbol().GetStartAddress().GetLineEntry()
                    if lineEntry.IsValid():
                        name += '\n' + lineEntry.file.fullpath + ':' + str(lineEntry.line)



            elif symbol_context.symbol.name is not None:
                name = symbol_context.symbol.name
                if options.mangled_name:
                    mangledName = symbol_context.symbol.GetMangledName()
                    name += ', ' + mangledName if mangledName else '[NONE]'

                if options.source_info:
                    lineEntry = symbol_context.GetSymbol().GetStartAddress().GetLineEntry()
                    if lineEntry.IsValid():
                        name += '\n' + lineEntry.file.fullpath + ':' + str(lineEntry.line)

            else:
                return_string += 'Can\'t find info for ' + str(symbol_context) + '\n\n'
                continue


            if options.load_address:
                str_addr = str(hex(symbol_context.GetSymbol().GetStartAddress().GetLoadAddress(target)))
                end_addr = str(hex(symbol_context.GetSymbol().GetEndAddress().GetLoadAddress(target)))
                return_string += ds.attrStr('[' + str_addr + '-' + end_addr + '] ', 'yellow') + name
            else:  
                return_string += name

            return_string += '\n\n'


    return return_string


def generate_main_executable_class_address_script(bundlePath = None, options=None):
    command_script = r'''
  @import ObjectiveC;
  @import Foundation;
  NSMutableString *retstr = [NSMutableString string];
  unsigned int count = 0;

  NSBundle *dsbundle = [NSBundle '''

    if bundlePath is not None:
        command_script += 'bundleWithPath:@"' + bundlePath + '"];'
    else:
        command_script += 'mainBundle];' 


    command_script += r'''
  const char *path = [[dsbundle executablePath] UTF8String];
  const char **allClasses = objc_copyClassNamesForImage(path, &count);
  for (int i = 0; i < count; i++) {
    Class cls = objc_getClass(allClasses[i]);
    if (!class_getSuperclass(cls)) {
      continue;
    }
    unsigned int methCount = 0;
    Method *methods = class_copyMethodList(cls, &methCount);
    for (int j = 0; j < methCount; j++) {
      Method meth = methods[j];
      '''
    if options.load_address or options.create_breakpoint:
        command_script += r'''
      NSString *w = (NSString *)[NSString stringWithFormat:@" [%p] ", method_getImplementation(meth)];
      NSString *methodName = [[[[[w stringByAppendingString:@"-["] stringByAppendingString:NSStringFromClass(cls)] stringByAppendingString:@" "] stringByAppendingString:NSStringFromSelector(method_getName(meth))] stringByAppendingString:@"]\n"]
      '''
    else:
        command_script += r'''
      NSString *methodName = [[[[@"-[" stringByAppendingString:NSStringFromClass(cls)] stringByAppendingString:@" "] stringByAppendingString:NSStringFromSelector(method_getName(meth))] stringByAppendingString:@"]\n"];
      '''
    command_script += r'''
      [retstr appendString:methodName];
    }

    unsigned int classMethCount = 0;
    Method *classMethods = class_copyMethodList(objc_getMetaClass(class_getName(cls)), &classMethCount);
    for (int j = 0; j < classMethCount; j++) {
      Method meth = classMethods[j];
      '''
    if options.load_address or options.create_breakpoint:
        command_script += r'''
      NSString *w = (NSString *)[NSString stringWithFormat:@" [%p] ", method_getImplementation(meth)];
      NSString *methodName = [[[[[w stringByAppendingString:@"+["] stringByAppendingString:NSStringFromClass(cls)] stringByAppendingString:@" "] stringByAppendingString:NSStringFromSelector(method_getName(meth))] stringByAppendingString:@"]\n"];
      '''
    else:
        command_script += r'''
      NSString *methodName = [[[[@"+[" stringByAppendingString:NSStringFromClass(cls)] stringByAppendingString:@" "] stringByAppendingString:NSStringFromSelector(method_getName(meth))] stringByAppendingString:@"]\n"];
      [retstr appendString:methodName];
      '''
    command_script += r'''
      [retstr appendString:methodName];
    }

    free(methods);
    free(classMethods);
  }
  free(allClasses);
  retstr
  '''
    return command_script


def generate_option_parser():
    usage = "usage: %prog [options] path/to/item"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    parser.add_option("-m", "--module",
                      action="store",
                      default=None,
                      dest="module",
                      help="Limit scope to a specific module")

    parser.add_option("-g", "--global_var",
                      action="store",
                      default=None,
                      dest="global_var",
                      help="Search for global variables in a module (i.e. static NSString woot) instead of functions")

    parser.add_option("-G", "--global_var_noeval",
                      action="store",
                      default=None,
                      dest="global_var_noeval",
                      help="Search for global variables in a module (i.e. static NSString woot) instead of functions")

    parser.add_option("-s", "--module_summary",
                      action="store_true",
                      default=False,
                      dest="module_summary",
                      help="Give the summary of return hits from the different modules")

    parser.add_option("-S", "--strings",
                      action="store_true",
                      default=False,
                      dest="strings",
                      help="Search the __TEXT.__cstring segment for a regular expression")

    parser.add_option("-M", "--mangled_name",
                      action="store_true",
                      default=False,
                      dest="mangled_name",
                      help="Get the mangled name of the function (i.e. Swift)")

    parser.add_option("-l", "--load_address",
                      action="store_true",
                      default=False,
                      dest="load_address",
                      help="Only print out the simple description with method name, don't print anything else")

    parser.add_option("-x", "--search_stripped_executable",
                      action="store",
                      default=None,
                      dest="stripped_executable",
                      help="Typically, a release executable will be stripped. This searches the executables Objective-C classes by using the Objective-C runtime")

    parser.add_option("-X", "--search_main_stripped_executable",
                      action="store_true",
                      default=False,
                      dest="stripped_executable_main",
                      help="Searches the main, stripped executable for the regex. This searches the executables Objective-C classes by using the Objective-C runtime")

    parser.add_option("-B", "--create_breakpoint",
                      action="store_true",
                      default=False,
                      dest="create_breakpoint",
                      help="Creates a breakpoint on the found functions. Only works with the -X or -x option. Use rb otherwise")

    parser.add_option("-i", "--source_info",
                      action="store_true",
                      default=False,
                      dest="source_info",
                      help="Print out the source info for an function hit, if available")
    return parser

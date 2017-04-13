# MIT License
# 
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
    'command script add -f sbt.handle_command sbt')

def handle_command(debugger, command, result, internal_dict):
    '''
    Symbolicate backtrace. Will symbolicate a stripped backtrace
    from an executable if the backtrace is using Objective-C 
    code. Currently doesn't work on aarch64 stripped executables
    but works great on x64 :]
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    if thread is None:
        result.SetError('LLDB must be paused to execute this command')
        return

    frame_addresses = []
    for f in thread.frames:
        frame_addresses.append(f.GetSymbol().GetStartAddress().GetLoadAddress(target))
    script = generate_executable_methods_script(frame_addresses)


    # debugger.HandleCommand('expression -lobjc -O -- ' + script)
    methods_dictionary = target.EvaluateExpression(script, generate_expression_options())

    for index, frame in enumerate(thread.frames):
        function = frame.GetFunction()
        symbol = frame.symbol
        
        # LLDB Generates this method if synthetic... i.e. it's stripped & we don't have symbolic info
        if symbol.synthetic:
            load_addr = symbol.addr.GetLoadAddress(target)

            children = methods_dictionary.GetNumChildren()
            symbol_name = symbol.name + r' ... unresolved womp womp'
            for i in range(children):
                key = long(methods_dictionary.GetChildAtIndex(i).GetChildMemberWithName('key').description)
                if key == load_addr:
                    symbol_name = methods_dictionary.GetChildAtIndex(i).GetChildMemberWithName('value').description
                    break
        else:
            symbol_name = symbol.name

        offset_str = ''
        offset = frame.addr.GetLoadAddress(target) - frame.symbol.addr.GetLoadAddress(target)
        if offset > 0:
            offset_str = '+ {}'.format(offset)
        frame_string = 'frame #{}: {} {}`{} {}'.format(index, hex(frame.addr.GetLoadAddress(target)), frame.module.file.basename, symbol_name, offset_str)
        result.AppendMessage(frame_string)



def generate_expression_options():
    expr_options = lldb.SBExpressionOptions()
    expr_options.SetIgnoreBreakpoints(True);
    expr_options.SetFetchDynamicValue(lldb.eDynamicCanRunTarget);
    expr_options.SetTimeoutInMicroSeconds (30*1000*1000) # 30 second timeout
    expr_options.SetUnwindOnError(True)
    expr_options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    expr_options.SetCoerceResultToId(False)
    return expr_options


def generate_executable_methods_script(frame_addresses):
    frame_addr_str = 'NSArray *ar = @['
    for f in frame_addresses:
        frame_addr_str += '@"' + str(f) + '",'

    frame_addr_str = frame_addr_str[:-1]
    frame_addr_str += '];'

    command_script = r'''
  @import ObjectiveC;
  @import Foundation;
  NSMutableDictionary *retdict = [NSMutableDictionary dictionary];
  unsigned int count = 0;
  const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
  const char **allClasses = (const char **)objc_copyClassNamesForImage(path, &count);
  for (int i = 0; i < count; i++) {
    Class cls = objc_getClass(allClasses[i]);
    if (!(Class)class_getSuperclass(cls)) {
      continue;
    }
    unsigned int methCount = 0;
    Method *methods = class_copyMethodList(cls, &methCount);
    for (int j = 0; j < methCount; j++) {
      Method meth = methods[j];
      id implementation = (id)method_getImplementation(meth);
      NSString *methodName = [[[[@"-[" stringByAppendingString:NSStringFromClass(cls)] stringByAppendingString:@" "] stringByAppendingString:NSStringFromSelector(method_getName(meth))] stringByAppendingString:@"]"];
      [retdict setObject:methodName forKey:(id)[@((uintptr_t)implementation) stringValue]];
    }
    
    unsigned int classMethCount = 0;
    
    Method *classMethods = class_copyMethodList(objc_getMetaClass(class_getName(cls)), &classMethCount);
    for (int j = 0; j < classMethCount; j++) {
      Method meth = classMethods[j];
      id implementation = (id)method_getImplementation(meth);
      NSString *methodName = [[[[@"+[" stringByAppendingString:NSStringFromClass(cls)] stringByAppendingString:@" "] stringByAppendingString:NSStringFromSelector(method_getName(meth))] stringByAppendingString:@"]"];
      [retdict setObject:methodName forKey:(id)[@((uintptr_t)implementation) stringValue]];
    }
    
    free(methods);
    free(classMethods);
  }
  free(allClasses);
  '''
    command_script += frame_addr_str
    command_script += r'''

  NSMutableDictionary *stackDict = [NSMutableDictionary dictionary];
  [retdict keysOfEntriesPassingTest:^BOOL(id key, id obj, BOOL *stop) {
    
    if ([ar containsObject:key]) {
      [stackDict setObject:obj forKey:key];
      return YES;
    }
    
    return NO;
  }];
  stackDict;
  '''
    return command_script

def generate_option_parser():
    usage = "usage: %prog"
    parser = optparse.OptionParser(usage=usage, prog="sbt")
    return parser
    
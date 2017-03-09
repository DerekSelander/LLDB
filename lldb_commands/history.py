

import lldb
import os
import shlex
import optparse
import lldb.utils.symbolication

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -c history.history history')
    debugger.HandleCommand('command alias slog_on expression -lobjc -O -- extern void turn_on_stack_logging(int); turn_on_stack_logging(1);')


class history:


    classes = {}
    def __init__(self, debugger, session_dict):
        pass

    def __call__(self, debugger, command, exe_ctx, result):
        command_args = shlex.split(command, posix=False)
        parser = generate_option_parser()
        debugger.SetAsync(False)
        try:
            (options, args) = parser.parse_args(command_args)
        except:
            result.SetError(parser.usage)
            return

        if not args:
            result.SetError('TODO make this relevant')
            return

        clean_command = ('').join(args)

        
        target = debugger.GetSelectedTarget()
        expr_options = lldb.SBExpressionOptions()
        expr_options.SetIgnoreBreakpoints(False);
        expr_options.SetFetchDynamicValue(lldb.eDynamicCanRunTarget);
        expr_options.SetTimeoutInMicroSeconds (30*1000*1000) # 30 second timeout
        expr_options.SetTryAllThreads (True)
        expr_options.SetUnwindOnError(False)
        expr_options.SetGenerateDebugInfo(True)
        expr_options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
        expr_options.SetCoerceResultToId(False)
        frame = debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
        if frame is None:
            result.SetError('You must have the process suspended in order to execute this command')
            return
        # debugger.HandleCommand('po ' + command_script)

        command_script = get_command_script(clean_command, options)
        # debugger.HandleCommand('expression -lobjc++ -g -O -- ' + command_script)
        expr_value = frame.EvaluateExpression (command_script, expr_options)
        
        
        if not expr_value.error.success:
            result.SetError(str(expr_value.error))
            return



        lldb_stackaddress = lldb.value(expr_value)
        frame_count = lldb_stackaddress.count

        frame_addresses = []
        function_addresses = []
        for i in range(lldb_stackaddress.count):
            val = lldb_stackaddress.addresses[i]

            load_addr = int(val.sbvalue.GetValue())
            frame_addresses.append(load_addr)

            addr = target.ResolveLoadAddress(load_addr)
            print (addr)
            function_addresses.append(addr.GetSymbol().GetStartAddress().GetLoadAddress(target))
            # print(addr.GetSymbol().GetStartAddress().GetLoadAddress(target))
            # print(addr.GetLineEntry().GetLine())

        # # debugger.HandleCommand('expression -g -O -lobjc++ -- ' + command_script)
        # print (expr_value)
        print(function_addresses)


        expr_options.SetCoerceResultToId(True)
        class_load_address_script = self.generate_main_executable_class_address_script()
        dict_value = frame.EvaluateExpression (class_load_address_script, expr_options)


    def get_short_help(self): 
        return "Monitors "

    def get_long_help(self): 
        return self.__doc__

    def generate_main_executable_class_address_script(self):
        command_script = r'''
  NSMutableDictionary *retdict = [NSMutableDictionary dictionary];
  unsigned int count = 0;
  const char *path = [[[NSBundle mainBundle] executablePath] UTF8String];
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
      IMP implementation = method_getImplementation(meth);
      NSString *methodName = [[[[@"-[" stringByAppendingString:NSStringFromClass(cls)] stringByAppendingString:@" "] stringByAppendingString:NSStringFromSelector(method_getName(meth))] stringByAppendingString:@"]"];
      [retdict setObject:methodName forKey:[@((uintptr_t)implementation) stringValue]];
    }
    
    unsigned int classMethCount = 0;
    
    Method *classMethods = class_copyMethodList(objc_getMetaClass(class_getName(cls)), &classMethCount);
    for (int j = 0; j < classMethCount; j++) {
      Method meth = classMethods[j];
      IMP implementation = method_getImplementation(meth);
      NSString *methodName = [[[[@"+[" stringByAppendingString:NSStringFromClass(cls)] stringByAppendingString:@" "] stringByAppendingString:NSStringFromSelector(method_getName(meth))] stringByAppendingString:@"]"];
      [retdict setObject:methodName forKey:@((uintptr_t)implementation)];
    }
    
    free(methods);
    free(classMethods);
  }
  free(allClasses);
  return retdict
  '''
        return command_script

def generate_module_search_sections_string(debugger):
    target = debugger.GetSelectedTarget()
    module_name = target.GetExecutable().GetBasename()

    module = target.FindModule(lldb.SBFileSpec(module_name))
    if not module.IsValid():
        result.SetError(
            "Unable to open module name '{}', to see list of images use 'image list -b'".format(module_name))
        return

    returnString = r'''
    uintptr_t addr = (uintptr_t)cls;
    if (!('''
    section = module.FindSection("__DATA")
    for idx, subsec in enumerate(section):
        lower_bounds = subsec.GetLoadAddress(target)
        upper_bounds = lower_bounds + subsec.file_size

        if idx != 0:
            returnString += ' || '
        returnString += '({} <= addr && addr <= {})'.format(lower_bounds, upper_bounds)

    dirtysection = module.FindSection("__DATA_DIRTY")
    for subsec in dirtysection:
        lower_bounds = subsec.GetLoadAddress(target)
        upper_bounds = lower_bounds + subsec.file_size
        returnString += ' || ({} <= addr && addr <= {})'.format(lower_bounds, upper_bounds)

    returnString += ')) { continue; }\n'
    return returnString
    

def get_command_script(address, options):
    command_script = r'''
   typedef struct $LLDBStackAddress {
     mach_vm_address_t *addresses;
     uint32_t count = 0;
   } $LLDBStackAddress;
   $LLDBStackAddress stackaddress;
   extern kern_return_t __mach_stack_logging_get_frames(task_t task, mach_vm_address_t address, mach_vm_address_t *stack_frames_buffer, uint32_t max_stack_frames, uint32_t *count);
   mach_vm_address_t address = (mach_vm_address_t)(''' + address + r''');
   task_t task = (task_t)mach_task_self(); 
   stackaddress.addresses = (mach_vm_address_t *)calloc(100, sizeof(mach_vm_address_t));
   __mach_stack_logging_get_frames(task, address, stackaddress.addresses, 100, &stackaddress.count);
  stackaddress'''
    return command_script

def generate_option_parser():
    usage = "usage: %prog [options] NSObjectSubclass"
    parser = optparse.OptionParser(usage=usage, prog="find")
    parser.add_option("-e", "--exact_match",
                      action="store_true",
                      default=False,
                      dest="exact_match",
                      help="Searches for exact matches of class, i.e. no subclasses")

    return parser
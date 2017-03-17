# Credit where credit is due. 
# This script was inspired by libBeagle https://github.com/heardrwt/RHObjectiveBeagle 
# which in turn was inspired by Saurik's 'choose' command in cycript http://www.cycript.org/
# which in turn was inspired by Apple's heap python script 'command script import lldb.macosx.heap'
# which (I think) in turn was inspired by Apple's heap_find.cpp sourcefile found here
# https://opensource.apple.com/source/lldb/lldb-179.1/examples/darwin/heap_find/heap/heap_find.cpp

# All have made great progress in their own right. 
# This tool improves upon its predecessors by adding options that lldb can use to filter queries
# For exmple, filtering all NSObject subclasses found within a given dynamic library
# i.e search NSObject -m UIKit

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
import lldb.utils.symbolication

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f search.search search')


def search(debugger, command, result, internal_dict):
    '''
    Finds all subclasses of a class. This class must by dynamic 
    (aka inherit from a NSObject class). Currently doesn't work 
    with NSString or NSNumber (tagged pointer objects). 

    NOTE: This script will leak memory

Examples:

    # Find all UIViews and subclasses of UIViews
    find UIView

    # Find all UIStatusBar instances
    find UIStatusBar

    # Find all UIViews, ignore subclasses
    find UIView  -e

    # Find all instances of UIViews (and subclasses) where tag == 5
    find UIView -c "[obj tag] == 5"
    '''

    command_args = shlex.split(command)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    if not args:
        result.SetError('Usage: find NSObjectSubclass\n\nUse \'help find\' for more details')
        return

    clean_command = ('').join(args)
    

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    if options.module:
        target = debugger.GetSelectedTarget()
        module = target.FindModule(lldb.SBFileSpec(options.module))
        if not module.IsValid():
            result.SetError(
                "Unable to open module name '{}', to see list of images use 'image list -b'".format(options.module))
            return
        options.module = generate_module_search_sections_string(module, target)


    interpreter.HandleCommand('po (Class)NSClassFromString(@\"{}\")'.format(clean_command), res)
    if 'nil' in res.GetOutput():
        result.SetError('Can\'t find class named "{}". Womp womp...'.format(clean_command))
        return

    objectiveC_class = 'NSClassFromString(@"{}")'.format(clean_command)
    command_script = get_command_script(objectiveC_class, options)

    expr_options = lldb.SBExpressionOptions()
    expr_options.SetIgnoreBreakpoints(True);
    expr_options.SetFetchDynamicValue(lldb.eNoDynamicValues);
    expr_options.SetTimeoutInMicroSeconds (30*1000*1000) # 30 second timeout
    expr_options.SetTryAllThreads (True)
    expr_options.SetUnwindOnError(True)
    expr_options.SetGenerateDebugInfo(True)
    expr_options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    expr_options.SetCoerceResultToId(True)
    # expr_options.SetAutoApplyFixIts(True)
    frame = debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()

    if frame is None:
        result.SetError('You must have the process suspended in order to execute this command')
        return
    # debugger.HandleCommand('po ' + command_script)

    # debugger.HandleCommand('expression -lobjc++ -g -O -- ' + command_script)
    expr_sbvalue = frame.EvaluateExpression (command_script, expr_options)
    count = expr_sbvalue.GetNumChildren(100000) # Actually goes up to 2^32 but this is more than enough    

    if not expr_sbvalue.error.success:
        result.SetError("\n***************************************\nerror: " + str(expr_sbvalue.error))
    else:
        if count > 1000:
            result.AppendWarning('Exceeded 1000 hits, try narrowing your search with the --condition option')
            result.AppendMessage (expr_sbvalue)
        else:
            if options.barebones:
                for val in expr_sbvalue:
                    val_description = val.GetTypeName() + ' [' + val.GetValue()  + ']'
                    result.AppendMessage(val_description)
            else:
                result.AppendMessage(expr_sbvalue.description)


def get_command_script(objectiveC_class, options):
    command_script = r'''//grab the zones in the current process
@import Foundation;
@import ObjectiveC;

typedef struct _DSSearchContext {
    Class query;
    CFMutableSetRef classesSet;
    CFMutableSetRef results;
} DSSearchContext;

auto task_peek = [](task_t task, vm_address_t remote_address, vm_size_t size, void **local_memory) -> kern_return_t {
    *local_memory = (void*) remote_address;
    return (kern_return_t)0;
};

vm_address_t *zones = NULL;
unsigned int count = 0;
unsigned int maxresults = ''' + str(options.max_results) + r'''
kern_return_t error = (kern_return_t)malloc_get_all_zones(0, 0, &zones, &count);

DSSearchContext *context = (DSSearchContext *)calloc(sizeof(DSSearchContext), 1);
int classCount = (int)objc_getClassList(NULL, 0);
CFMutableSetRef set = (CFMutableSetRef)CFSetCreateMutable(0, classCount, NULL);
Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * classCount);
objc_getClassList(classes, classCount);


typedef struct malloc_introspection_t {
     kern_return_t (*enumerator)(task_t task, void *, unsigned type_mask, vm_address_t zone_address, memory_reader_t reader, vm_range_recorder_t recorder);
} malloc_introspection_t;

 typedef struct malloc_zone_t {
     void *reserved1[9];
     const char  *zone_name;
     void *reserved2[2];
     struct malloc_introspection_t   *introspect;
     unsigned    version;
     void *reserved3[3];
 } malloc_zone_t; 
  
for (int i = 0; i < classCount; i++) {
    Class cls = classes[i];
    CFSetAddValue(set, (__bridge const void *)(cls));
}
  
// Setup callback context
context->results = (CFMutableSetRef)CFSetCreateMutable(0, maxresults, NULL);
context->classesSet = set;
context->query =  ''' + objectiveC_class + r''';
for (unsigned i = 0; i < count; i++) {
    const malloc_zone_t *zone = (const malloc_zone_t *)zones[i];
    if (zone == NULL || zone->introspect == NULL){
        continue;
    }

    //for each zone, enumerate using our enumerator callback
    zone->introspect->enumerator(0, context, 1, zones[i], task_peek, 
    [] (task_t task, void *baton, unsigned type, vm_range_t *ranges, unsigned count) -> void {

        DSSearchContext *context =  (DSSearchContext *)baton;
        Class query = context->query;
        CFMutableSetRef classesSet = context->classesSet;
        CFMutableSetRef results = context->results;

        int maxCount = ''' + str(options.max_results) + ''';
        size_t querySize = (size_t)class_getInstanceSize(query);
      
        int (^isBlackListClass)(Class) = ^int(Class aClass) {
            NSString *className = (NSString *)NSStringFromClass(aClass);

            if ([@"_NSZombie_" isEqualToString:className]) return 1;
            if ([@"NSPlaceholderMutableString" isEqualToString:className]) return 1;
            if ([@"__ARCLite__" isEqualToString:className]) return 1;
            if ([@"__NSCFCalendar" isEqualToString:className]) return 1;
            if ([@"__NSCFTimer" isEqualToString:className]) return 1;
            if ([@"NSCFTimer" isEqualToString:className]) return 1;
            if ([@"__NSMessageBuilder" isEqualToString:className]) return 1;
            if ([@"__NSGenericDeallocHandler" isEqualToString:className]) return 1;
            if ([@"NSTaggedPointerStringCStringContainer" isEqualToString:className]) return 1;
            if ([@"NSAutoreleasePool" isEqualToString:className]) return 1;
            if ([@"NSPlaceholderNumber" isEqualToString:className]) return 1;
            if ([@"NSPlaceholderString" isEqualToString:className]) return 1;
            if ([@"NSPlaceholderValue" isEqualToString:className]) return 1;
            if ([@"Object" isEqualToString:className]) return 1;
            if ([@"NSPlaceholderNumber" isEqualToString:className]) return 1;
            if ([@"VMUArchitecture" isEqualToString:className]) return 1;
            if ([className hasPrefix:@"__NSPlaceholder"]) return 1;

            return 0;
        };
      
        for (int i = 0; i < count; i++) {
            if (i >= maxCount || CFSetGetCount(results) >= maxCount) {
                break;
            }
        
            // test 1
            if (ranges[i].size < querySize) {
              continue;
            }

        
            vm_address_t potentialObject = ranges[i].address;
         
            Class potentialClass = object_getClass((__bridge id)((void *)potentialObject));

            // test 2
            if (!(int)CFSetContainsValue(classesSet, (__bridge const void *)(potentialClass))) {
                continue;
            }
            
            // test 3
            if ((size_t)malloc_good_size((size_t)class_getInstanceSize(potentialClass)) != ranges[i].size) {
                continue;
            }
            
            // Yay, if we are here this is likely an NSObject
            if (isBlackListClass(potentialClass)) {
                continue;
            }
            
            id obj = (__bridge id)(void *)potentialObject;

            if (!(BOOL)[obj respondsToSelector:@selector(description)]) {
                continue;
            }
            '''

    if options.exact_match:
        command_script  += 'if ((int)[potentialClass isMemberOfClass:query]'
    else: 
        command_script += 'if ((int)[potentialClass isSubclassOfClass:query]'

    if options.condition:
        cmd = options.condition
        command_script += '&& (int)(' + options.condition + ')'

    command_script += r') {'

    if options.module:
        command_script += options.module

    command_script += r'''
                CFSetAddValue(results, (__bridge const void *)(obj));
            }
        }
     });
}
 
CFIndex index = (CFIndex)CFSetGetCount(context->results);
  
const void **values = (const void **)calloc(index, sizeof(id));
CFSetGetValues(context->results, values);
    
NSMutableArray *outputArray = [NSMutableArray arrayWithCapacity:index];
for (int i = 0; i < index; i++) {
    id object = (__bridge id)(values[i]);
    [outputArray addObject:object];
}
  
  
free(values);
free(set);
free(context); 
free(classes);'''

    if options.perform_action:
        command_script += r'''
[outputArray enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop){;
    '''
        command_script += options.perform_action + ' }];\n'
     
     
    command_script += 'outputArray;'
    return command_script

def generate_module_search_sections_string(module, target):

    returnString = r'''
    uintptr_t addr = (uintptr_t)potentialClass;
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

def generate_option_parser():
    usage = "usage: %prog [options] NSObjectSubclass"
    parser = optparse.OptionParser(usage=usage, prog="search")
    parser.add_option("-e", "--exact_match",
                      action="store_true",
                      default=False,
                      dest="exact_match",
                      help="Searches for exact matches of class, i.e. no subclasses")

    parser.add_option("-c", "--condition",
                      action="store",
                      default=None,
                      dest="condition",
                      help="a conditional expression to filter hits. Objective-C input only. Use 'obj' to reference object")

    parser.add_option("-p", "--perform-action",
                      action="store",
                      default=None,
                      dest="perform_action",
                      help="a conditional expression to filter hits. Objective-C input only. Use 'obj' to reference object")

    parser.add_option("-m", "--module",
                      action="store",
                      default=None,
                      dest="module",
                      help="Filters results to only be in a certain module. i.e. -m UIKit")

    parser.add_option("-b", "--barebones",
                      action="store_true",
                      default=False,
                      dest="barebones",
                      help="Only dump out the classname and pointer, no description")

    parser.add_option("-x", "--max_results",
                      action="store",
                      default=200,
                      type="int",
                      dest="max_results",
                      help="Specifies the maximum return count that the script should return")
    return parser

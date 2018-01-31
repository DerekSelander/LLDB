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
import ds
import optparse
import lldb.utils.symbolication


s = ""
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f search.search search -h "Searches heap for instances')


def search(debugger, command, exe_ctx, result, internal_dict):
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

    if not ds.isProcStopped():
        result.SetError(ds.attrStr('You must have the process suspended in order to execute this command', 'red'))
        return

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
        target = exe_ctx.target
        module = target.FindModule(lldb.SBFileSpec(options.module))
        if not module.IsValid():
            result.SetError(
                "Unable to open module name '{}', to see list of images use 'image list -b'".format(options.module))
            return
        options.module = generate_module_search_sections_string(module, target)


    if options.pointer_reference:
        objectiveC_class = '(uintptr_t *){}'.format(clean_command)
        if options.pointer_reference and (options.exact_match or options.module or options.module or options.condition or options.perform_action):
            result.SetError("Can only use the --pointer_reference with --barebones")
    else:
        
        interpreter.HandleCommand('expression -lobjc -O -- (Class)NSClassFromString(@\"{}\")'.format(clean_command), res)
        if 'nil' in res.GetOutput():
            result.SetError('Can\'t find class named "{}". Womp womp...'.format(clean_command))
            return
        objectiveC_class = 'NSClassFromString(@"{}")'.format(clean_command)

    command_script = get_command_script(objectiveC_class, options)
    # print command_script
    # return

    expr_options = lldb.SBExpressionOptions()
    expr_options.SetIgnoreBreakpoints(True);
    expr_options.SetFetchDynamicValue(lldb.eNoDynamicValues);
    expr_options.SetTimeoutInMicroSeconds (30*1000*1000) # 30 second timeout
    expr_options.SetTryAllThreads (False)
    expr_options.SetTrapExceptions(False)
    expr_options.SetUnwindOnError(True)
    expr_options.SetGenerateDebugInfo(True)
    expr_options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    expr_options.SetCoerceResultToId(True)
    # expr_options.SetAutoApplyFixIts(True)
    frame = exe_ctx.frame

    if frame is None:
        result.SetError('You must have the process suspended in order to execute this command')
        return
    # debugger.HandleCommand('po ' + command_script)

    # debugger.HandleCommand('expression -lobjc++ -g -O -- ' + command_script)
    # return
    # print(command_script)
    expr_sbvalue = frame.EvaluateExpression(command_script, expr_options)

    if not expr_sbvalue.error.success:
        result.SetError("\n**************************************\nerror: " + str(expr_sbvalue.error))
        return
    
    val = lldb.value(expr_sbvalue)
    count = val.count.sbvalue.unsigned
    global s
    s = val 

    if count > 100:
        result.AppendWarning('Exceeded 100 hits, try narrowing your search with the --condition option')
        count = 100

    if options.pointer_reference:
        for i in range(count):
            v = val.values[i].sbvalue
            offset = val.offsets[i].sbvalue.unsigned
            val_description = ds.attrStr(str(v.GetTypeName()), 'cyan') + ' [' + ds.attrStr(str(v.GetValue()), 'yellow')  + ']' + ' + '  + ds.attrStr(str(offset), 'yellow')
            result.AppendMessage(val_description)
    else:
	    if options.barebones:
	        for i in range(count):
	            v = val.values[i].sbvalue
	            val_description = ds.attrStr(str(v.GetTypeName()), 'cyan') + ' [' + ds.attrStr(str(v.GetValue()), 'yellow')  + ']'
	            result.AppendMessage(val_description)
	    else:
	        for i in range(count):
	            v = val.values[i].sbvalue
	            if not v.description:
	                continue
	            desc = v.description 
	            result.AppendMessage(desc + '\n')


def get_command_script(objectiveC_class, options):
    command_script = r'''//grab the zones in the current process
@import Foundation;
@import ObjectiveC;

typedef struct _DSSearchContext {
    Class query;
    CFMutableSetRef classesSet;
    CFMutableSetRef results;
    uintptr_t *pointerRef;
    int *offsets;
    CFMutableArrayRef ptrRefResults;

} DSSearchContext;

auto task_peek = [](task_t task, vm_address_t remote_address, vm_size_t size, void **local_memory) -> kern_return_t {
    *local_memory = (void*) remote_address;
    return (kern_return_t)0;
};

vm_address_t *zones = NULL;
unsigned int count = 0;
unsigned int maxresults = ''' + str(options.max_results) + r''';
kern_return_t error = (kern_return_t)malloc_get_all_zones(0, 0, &zones, &count);

DSSearchContext *_ds_context = (DSSearchContext *)calloc(1, sizeof(DSSearchContext));
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
_ds_context->results = (CFMutableSetRef)CFSetCreateMutable(0, maxresults, NULL);
_ds_context->ptrRefResults = (CFMutableArrayRef)CFArrayCreateMutable(0, maxresults, NULL);
_ds_context->classesSet = set;
_ds_context->offsets = (int *)calloc(maxresults, sizeof(int));
''' 
    if options.pointer_reference:
        command_script += r'''_ds_context->pointerRef =  ''' + objectiveC_class + ';' # actually ptr address here
    else:
        command_script += r'''_ds_context->query =  ''' + objectiveC_class + ';'
    command_script += r'''
for (unsigned i = 0; i < count; i++) {
    malloc_zone_t *zone = (malloc_zone_t *)zones[i];
    if (zone == NULL || zone->introspect == NULL){
        continue;
    }


    //for each zone, enumerate using our enumerator callback
    zone->introspect->enumerator(0, _ds_context, 1, zones[i], task_peek, 
    [] (task_t task, void *baton, unsigned type, vm_range_t *ranges, unsigned count) -> void {

        DSSearchContext *_ds_context =  (DSSearchContext *)baton;
        CFMutableSetRef classesSet = _ds_context->classesSet;
        CFMutableSetRef results = _ds_context->results;
        CFMutableArrayRef ptrRefResults = _ds_context->ptrRefResults;
        int *offsets = _ds_context->offsets; 
        int maxCount = ''' + str(options.max_results) + ''';

      
        for (int j = 0; j < count; j++) {
            if (CFSetGetCount(results) >= maxCount) {
                break;
            }

            vm_address_t potentialObject = ranges[j].address;

            '''
    if not options.pointer_reference:
        command_script += r'''
        Class query = _ds_context->query;
        size_t querySize = (size_t)class_getInstanceSize(query);

        // test 1
        if (ranges[j].size < querySize) {
          continue;
        }

        // ignore tagged pointer stuff 
        if ((0xFFFF800000000000 & potentialObject) != 0) {
            continue;
        }

        // test 4 is a tagged pointer 0x8000000000000000
        if ((potentialObject & 0x8000000000000000) == 0x8000000000000000) {
            continue;
        }
        '''

    command_script += r'''
         
	        Class potentialClass = object_getClass((__bridge id)((void *)potentialObject));

	        // test 2
	        if (!(int)CFSetContainsValue(classesSet, (__bridge const void *)(potentialClass))) {
	            continue;
	        }
	        
	        // test 3
	        if ((size_t)malloc_good_size((size_t)class_getInstanceSize(potentialClass)) != ranges[j].size) {
	            continue;
	        }



	        // TODO, I don't think? This is malloc'ing anything but don't know yet
		    NSString *className = (NSString *)NSStringFromClass(potentialClass);
		    if ([@"_NSZombie_" isEqualToString:className])  { continue };
		    if ([@"__ARCLite__" isEqualToString:className])  { continue };
		    if ([@"__NSCFCalendar" isEqualToString:className])  { continue };
		    if ([@"__NSCFTimer" isEqualToString:className])  { continue };
		    if ([@"NSCFTimer" isEqualToString:className])  { continue };
		    if ([@"__NSMessageBuilder" isEqualToString:className])  { continue };
		    if ([@"__NSGenericDeallocHandler" isEqualToString:className])  { continue };
		    if ([@"NSAutoreleasePool" isEqualToString:className])  { continue };
		    if ([@"Object" isEqualToString:className])  { continue };
		    if ([@"VMUArchitecture" isEqualToString:className])  { continue };

	        
	        id obj = (__bridge id)(void *)potentialObject;

	        if (!(BOOL)[obj respondsToSelector:@selector(description)]) {
	            continue;
	        }
	        '''

    if options.pointer_reference:
        command_script += r'''
	        size_t enumeratorSize = sizeof(uintptr_t*);
	        uintptr_t* ptr_objc = (uintptr_t*)ranges[j].address;
	        long pointerMask = 0L - sizeof(uintptr_t*);
	        uintptr_t *ptrRef = _ds_context->pointerRef;

	        size_t totalSize = ranges[j].size / sizeof(uintptr_t *);
	        for (int z = 0; z < totalSize; z++) {
	            if(ptr_objc[z] == ptrRef) {
	                offsets[CFArrayGetCount(ptrRefResults)] = z * enumeratorSize;
	                CFArrayAppendValue(ptrRefResults, obj);
	            }
	        }

    '''
    else:
        if options.exact_match:
            command_script  += 'if ((int)[potentialClass isMemberOfClass:query]'
        else: 
            command_script += 'if ((int)[[potentialClass class] isSubclassOfClass:query]'

        if options.condition:
            cmd = options.condition
            command_script += '&& (BOOL)(' + options.condition + ')'

        command_script += r') {'

        if options.module:
            command_script += options.module

        command_script += r'''
                CFSetAddValue(results, (__bridge const void *)(obj));
            } 
        '''
    command_script += r'''
	        }
     });
}
 
CFIndex index = (CFIndex)CFSetGetCount(_ds_context->results);
  
typedef struct $LLDBHeapObjects {
    const void **values;
    uint32_t count = 0;
    int *offsets;
} $LLDBHeapObjects;

$LLDBHeapObjects lldbheap;

lldbheap.values = (const void **)calloc(index, sizeof(id));
CFSetGetValues(_ds_context->results, lldbheap.values);
lldbheap.count = index;  
''' 
    if options.pointer_reference:
        command_script += r'''
lldbheap.offsets = _ds_context->offsets;
CFArrayGetValues(_ds_context->ptrRefResults, CFRangeMake(0, CFArrayGetCount(_ds_context->ptrRefResults)),lldbheap.values);
lldbheap.count = CFArrayGetCount(_ds_context->ptrRefResults);
	'''

	command_script += r'''
free(set);
free(_ds_context->ptrRefResults);
free(_ds_context); 
free(classes);'''

    if options.perform_action:
        command_script += r'''
        for (int i = 0; i < index; i++) {
            id obj = ((id)lldbheap.values[i]);

    '''
        command_script += options.perform_action + ' };\n (void)[CATransaction flush];'
     
     
    command_script += 'lldbheap;'
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
                      help="Perform an action on every returned query. Objective-C input only. Use 'obj' to reference object")

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

    parser.add_option("-r", "--reference",
                      action="store_true",
                      default=False,
                      dest="pointer_reference",
                      help="Expects a pointer instead of a class, searches for references to that pointer in a class")
    return parser

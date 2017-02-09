import lldb
import os
import shlex
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f find.find find')


def find(debugger, command, result, internal_dict):


    command_args = shlex.split(command)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    clean_command = ('').join(args)
    

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    interpreter.HandleCommand('po (Class)NSClassFromString(@\"{}\")'.format(clean_command), res)
    if 'nil' in res.GetOutput():
        result.SetError('Can\'t find class named "{}". Womp womp...'.format(clean_command))
        return

    objectiveC_class = 'NSClassFromString(@"{}")'.format(clean_command)
    command_script = get_command_script(objectiveC_class)

    debugger.HandleCommand('po ' + command_script)



def get_command_script(objectiveC_class):
    command_script = r'''//grab the zones in the current process
@import Foundation;
@import ObjectiveC;

typedef struct _DSSearchContext {
    Class query;
    CFMutableSetRef classesSet;
    CFMutableSetRef results;
} DSSearchContext;

vm_address_t *zones = NULL;
unsigned int count = 0;
kern_return_t error = (kern_return_t)malloc_get_all_zones(0, 0, &zones, &count);

DSSearchContext *context = (DSSearchContext *)calloc(sizeof(DSSearchContext), 1);
int classCount = (int)objc_getClassList(NULL, 0);
CFMutableSetRef set = (CFMutableSetRef)CFSetCreateMutable(0, classCount, NULL);
Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * classCount);
objc_getClassList(classes, classCount);
  
for (int i = 0; i < classCount; i++) {
    Class cls = classes[i];
    CFSetAddValue(set, (__bridge const void *)(cls));
}
  
// Setup callback context
context->results = (CFMutableSetRef)CFSetCreateMutable(0, 0, NULL);
context->classesSet = set;
context->query =  ''' + objectiveC_class + r''';
for (unsigned i = 0; i < count; i++) {
    const malloc_zone_t *zone = (const malloc_zone_t *)zones[i];
    if (zone == NULL || zone->introspect == NULL){
        continue;
    }

    //for each zone, enumerate using our enumerator callback
    zone->introspect->enumerator(0, context, 1, zones[i], NULL, 
    [] (task_t task, void *baton, unsigned type, vm_range_t *ranges, unsigned count) -> void { // Inline function trick lifted from heap.py, pretty cool, right? :]

        DSSearchContext *context =  (DSSearchContext *)baton;
        Class query = context->query;
        CFMutableSetRef classesSet = context->classesSet;
        CFMutableSetRef results = context->results;
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
            
            id actualObject = (__bridge id)(void *)potentialObject;
            if ((int)[potentialClass isSubclassOfClass:query]) {
                CFSetAddValue(results, (__bridge const void *)(actualObject));
                printf("%s\n", (char *)[[actualObject description] UTF8String]);
            }
        }

     });
}
  
CFIndex index = (CFIndex)CFSetGetCount(context->results);
  
  
const void **values = (const void **)calloc(index, sizeof(id));
CFSetGetValues(context->results, values);
                 
//for (int i = 0; i < index; i++) {
    //id object = (__bridge id)(values[i]);
    //// NSLog(@"%@", object);
//}
  
free(values);
free(set);
free(context); 
free(classes);
'''

    return command_script

def generate_option_parser():
    usage = "usage: %prog [options] path/to/item"
    parser = optparse.OptionParser(usage=usage, prog="yoink")
    parser.add_option("-o", "--open_immediately",
                      action="store_true",
                      default=False,
                      dest="open_immediately",
                      help="Opens the copied item immediately using the default 'open' cmd, useful for pics")

    parser.add_option("-c", "--copy_file_path",
                      action="store_true",
                      default=False,
                      dest="copy_file_path",
                      help="Copies the file path to the clipboard")

    return parser
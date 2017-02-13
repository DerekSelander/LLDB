

import lldb
import os
import shlex
import optparse
import lldb.utils.symbolication


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f dump_classes.dump_classes dump_classes')


def dump_classes(debugger, command, result, internal_dict):
    '''
    Dumps all the NSObject inherited classes in the process.
    If you give it a module that exists on disk, it will dump only the classes 
    within that module. You can also filter out classes to only a certain type
    of class.

Examples:

    # Dump ALL the NSObject classes within the process
    (lldb) dump_classes 

    # Dump all the classes that are a UIViewController within the process
    (lldb) dump_classes -f UIViewController

    # Dump all classes in CKConfettiEffect NSBundle that are UIView subclasses
    (lldb) dump_classes /System/Library/Messages/iMessageEffects/CKConfettiEffect.bundle/CKConfettiEffect -f UIView

    '''

    command_args = shlex.split(command)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    if not args:
        # result.SetError('Usage: find NSObjectSubclass\n\nUse \'help find\' for more details')
        clean_command = None
        # return
    else:
        clean_command = ('').join(args)

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    command = get_command_script(options, clean_command)
    if options.filter and clean_command:
        print('Dumping classes for: ' + clean_command +
              ', with filter: ' + options.filter)
    elif clean_command:
        print('Dumping classes for: ' + clean_command)
    else:
        print('Dumping all classes...')
    debugger.HandleCommand('expression -lobjc -O -- ' + command)


def get_command_script(options, clean_command=None):
    command_script = r'''
  @import ObjectiveC;
  unsigned int count = 0;

  '''
    if clean_command:
      command_script += '  const char **allClasses = objc_copyClassNamesForImage("' + clean_command + '", &count);'
    else:
        command_script += 'Class *allClasses = objc_copyClassList(&count);\n'

    command_script += '''  NSMutableArray *classes = [NSMutableArray arrayWithCapacity:count];
  for (int i = 0; i < count; i++) {
    Class cls =  '''

    command_script += 'objc_getClass(allClasses[i]);' if clean_command else 'allClasses[i];'

    if options.filter is None:
        command_script += r'''
        if (count > 200) {
          printf("%s\n", class_getName(cls));
        } else {
          [classes addObject:cls];
        }
  }'''
    else:
        command_script += '\nif (class_getSuperclass(cls) && (BOOL)[cls isSubclassOfClass:[' + str(options.filter) + r''' class]]) {    

         if (count > 200) {
          printf("%s\n", class_getName(cls));
        } else {
          [classes addObject:cls];
        }  
      }
    }'''


    command_script += '\n  free(allClasses);\n  [classes description]'

    return command_script


def generate_option_parser():
    usage = "usage: %prog [options] /optional/path/to/executable/or/bundle"
    parser = optparse.OptionParser(usage=usage, prog="dump_classes")

    parser.add_option("-f", "--filter",
                      action="store",
                      default=None,
                      dest="filter",
                      help="List all the classes in the module that are subclasses of class. -f UIView")
    return parser

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
import shlex
import optparse
import lldb.utils.symbolication


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f dclass.dclass dclass')


def dclass(debugger, command, result, internal_dict):
    '''
    Dumps all the NSObject inherited classes in the process. If you give it a 
    module that exists on disk, it will dump only the classes within that module. 
    You can also filter out classes to only a certain type and can also generate 
    a header file for a specific class.

Examples:

    # Dump ALL the NSObject classes within the process
    dclass 

    # Dump all the classes that are a UIViewController within the process
    dclass -f UIViewController

    # Dump all classes in CKConfettiEffect NSBundle that are UIView subclasses
    dclass /System/Library/Messages/iMessageEffects/CKConfettiEffect.bundle/CKConfettiEffect -f UIView

    # Generate a header file for the class specified:
    dclass -g UIView

    # Generate a protocol that you can cast an object to. Ideal when working with private classes at dev time
    dclass -p UIView

    '''

    command_args = shlex.split(command, posix=False)
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
    if not args and options.generate_header:
        result.SetError('Need to supply class for option')
        return
    else:
        clean_command = ('').join(args)

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    target = debugger.GetSelectedTarget()
    if options.module is not None:
        module = target.FindModule(lldb.SBFileSpec(options.module))
        if not module.IsValid():
            result.SetError(
                "Unable to open module name '{}', to see list of images use 'image list -b'".format(options.module))
            return

    if options.conforms_to_protocol is not None:
        interpreter.HandleCommand('expression -lobjc -O -- (id)NSProtocolFromString(@\"{}\")'.format(options.conforms_to_protocol), res)
        if 'nil' in res.GetOutput() or not res.GetOutput():
            result.SetError("No such Protocol name '{}'".format(options.conforms_to_protocol))
            return
        res.Clear()

    if options.generate_header or options.generate_protocol:
        command_script = generate_header_script(options, clean_command)
    else:
        command_script = generate_class_dump(debugger, options, clean_command)

    if options.generate_header or options.generate_protocol:
        interpreter.HandleCommand('expression -lobjc -O -- (Class)NSClassFromString(@\"{}\")'.format(clean_command), res)
        if 'nil' in res.GetOutput():
            result.SetError('Can\'t find class named "{}". Womp womp...'.format(clean_command))
            return
        res.Clear()

        if options.generate_protocol: 
          filepath = "/tmp/DS_" + clean_command + "Protocol.h"
        else:  
          filepath = "/tmp/" + clean_command + ".h"
        interpreter.HandleCommand('expression -lobjc -O -- ' + command_script, res)
        # debugger.HandleCommand('expression -lobjc -O -g -- ' + command_script)
        if res.GetError():
            result.SetError(res.GetError()) 
            return
        contents = res.GetOutput()

        create_or_touch_filepath(filepath, contents)
        print('Written output to: ' + filepath + '... opening file')
        os.system('open -R ' + filepath)
    else: 
        if options.filter and clean_command:
            result.AppendMessage('Dumping classes for: ' + clean_command + ', with filter: ' + options.filter)
        elif clean_command:
            result.AppendMessage('Dumping classes for: ' + clean_command)
        elif options.module and options.filter:
            result.AppendMessage('Dumping all classes in ' + options.module + ', with filter: ' + options.filter)
        elif options.module:
            result.AppendMessage('Dumping all classes in ' + options.module)
        elif options.conforms_to_protocol:
            result.AppendMessage('Dumping all classes which conform to ' + options.conforms_to_protocol)
        else:
            result.AppendMessage('Dumping all classes')

        interpreter.HandleCommand('expression -lobjc -O -- ' + command_script, res)
        # debugger.HandleCommand('expression -lobjc -O -g -- ' + command_script)
        if res.GetError():
            result .SetError(res.GetError())
            return
        result.AppendMessage('************************************************************')
        if res.Succeeded(): 
            result.AppendMessage(res.GetOutput())


def generate_class_dump(debugger, options, clean_command=None):
    command_script = r'''
  @import ObjectiveC;
  @import Foundation;
  unsigned int count = 0;

  '''
    if clean_command:
        command_script += '  const char **allClasses = objc_copyClassNamesForImage("' + clean_command + '", &count);'
    else:
        command_script += 'Class *allClasses = objc_copyClassList(&count);\n'

    if options.regular_expression is not None: 
        command_script += '  NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"' + options.regular_expression + '" options:0 error:nil];\n'

    command_script += '''  NSMutableString *classesString = [NSMutableString string];
  for (int i = 0; i < count; i++) {
    Class cls =  '''

    command_script += 'objc_getClass(allClasses[i]);' if clean_command else 'allClasses[i];'
    if options.module is not None: 
        command_script += generate_module_search_sections_string(options.module, debugger)

    if options.conforms_to_protocol is not None:
      command_script +=  'if (!class_conformsToProtocol(cls, NSProtocolFromString(@"'+ options.conforms_to_protocol + '"))) { continue; }'
  

    command_script += '  NSString *clsString = (NSString *)NSStringFromClass(cls);\n'
    if options.regular_expression is not None:
        command_script += r'''
    NSUInteger matches = (NSUInteger)[regex numberOfMatchesInString:clsString options:0 range:NSMakeRange(0, [clsString length])];
    if (matches == 0) {
      continue;
    }
        '''
   

    if options.filter is None:
        if options.verbose: 
            command_script += r'''
        NSString *imageString = [[[[NSString alloc] initWithUTF8String:class_getImageName(cls)] lastPathComponent] stringByDeletingPathExtension];
        [classesString appendString:imageString];
        [classesString appendString:@": "];
        '''


        command_script += r'''
          [classesString appendString:(NSString *)clsString];
          [classesString appendString:@"\n"];
  }'''
    else:
        command_script += '\n    if (class_getSuperclass(cls) && (BOOL)[cls isSubclassOfClass:(Class)NSClassFromString(@"' + str(options.filter) + '")]) {\n'    
        if options.verbose: 
            command_script += r'''
        NSString *imageString = [[[[NSString alloc] initWithUTF8String:class_getImageName(cls)] lastPathComponent] stringByDeletingPathExtension];
        [classesString appendString:imageString];
        [classesString appendString:@": "];
        '''
        command_script += r'''
          [classesString appendString:(NSString *)clsString];
          [classesString appendString:@"\n"];
      }
    }'''

    command_script += '\n  free(allClasses);\n  [classesString description];'

    return command_script

def generate_module_search_sections_string(module_name, debugger):
    target = debugger.GetSelectedTarget()

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

def generate_header_script(options, class_to_generate_header):
    script = '@import @ObjectiveC;\n'
    script += 'NSString *className = @"' + str(class_to_generate_header) + '";\n'
    script += r'''
  //Dang it. LLDB JIT Doesn't like NSString stringWithFormat on device. Need to use stringByAppendingString instead

  // Runtime declarations in case we're running on a stripped executable
  typedef struct objc_method *Method;
  typedef struct objc_ivar *Ivar;
  typedef struct objc_category *Category;
  typedef struct objc_property *objc_property_t;

  NSMutableString *returnString = [NSMutableString string];
  // Properties
  NSMutableString *generatedProperties = [NSMutableString string];
  NSMutableSet *blackListMethodNames = [NSMutableSet set];
  NSMutableSet *exportedClassesSet = [NSMutableSet set];
  NSMutableSet *exportedProtocolsSet = [NSMutableSet set];
  [blackListMethodNames addObjectsFromArray:@[@".cxx_destruct", @"dealloc"]];
  unsigned int propertyCount = 0;
  Class cls = NSClassFromString(className);
  objc_property_t *properties = (objc_property_t *)class_copyPropertyList(cls, &propertyCount);
  NSCharacterSet *charSet = [NSCharacterSet characterSetWithCharactersInString:@","];
  
  NSString *(^argumentBlock)(NSString *) = ^(NSString *arg) {
    if ([arg isEqualToString:@"@"]) {
      return @"id";
    } else if ([arg isEqualToString:@"v"]) {
      return @"void";
    } else if ([arg hasPrefix:@"{CGRect"]) {
      return @"CGRect";
    } else if ([arg hasPrefix:@"{CGPoint"]) {
      return @"CGPoint";
    } else if ([arg hasPrefix:@"{CGSize"]) {
      return @"CGSize";
    } else if ([arg isEqualToString:@"q"]) {
      return @"NSInteger";
    } else if ([arg isEqualToString:@"B"]) {
      return @"BOOL";
    } else if ([arg isEqualToString:@":"]) {
        return @"SEL";
    } else if ([arg isEqualToString:@"d"]) {
      return @"CGFloat";
    } else if ([arg isEqualToString:@"@?"]) { // A block?
      return @"id";
    }
    return @"void *";
  };

  NSMutableSet *blackListPropertyNames = [NSMutableSet setWithArray:@[@"hash", @"superclass", @"class", @"description", @"debugDescription"]];
  for (int i = 0; i < propertyCount; i++) {
    objc_property_t property = properties[i];
    NSString *attributes = [NSString stringWithUTF8String:(char *)property_getAttributes(property)];
    
    NSString *name = [NSString stringWithUTF8String:(char *)property_getName(property)];
    if ([blackListPropertyNames containsObject:name]) {
      continue;
    }
    NSMutableString *generatedPropertyString = [NSMutableString stringWithString:@"@property ("];
    
    NSScanner *scanner = [[NSScanner alloc] initWithString:attributes];
    [scanner setCharactersToBeSkipped:charSet];
    
    BOOL multipleOptions = 0;
    NSString *propertyType;
    NSString *parsedInput;
    while ([scanner scanUpToCharactersFromSet:charSet intoString:&parsedInput]) {
      if ([parsedInput isEqualToString:@"N"]) {
        if (multipleOptions) {
          [generatedPropertyString appendString:@", "];
        }
        
        [generatedPropertyString appendString:@"nonatomic"];
        multipleOptions = 1;
      } else if ([parsedInput isEqualToString:@"W"]) {
        if (multipleOptions) {
          [generatedPropertyString appendString:@", "];
        }
        
        [generatedPropertyString appendString:@"weak"];
        multipleOptions = 1;
      } else if ([parsedInput hasPrefix:@"G"]) {
        if (multipleOptions) {
          [generatedPropertyString appendString:@", "];
        }
       [generatedPropertyString appendString:(NSString *)@"getter="];
       [generatedPropertyString appendString:(NSString *)[parsedInput substringFromIndex:1]];
       [blackListMethodNames addObject:[parsedInput substringFromIndex:1]];
        multipleOptions = 1;
      } else if ([parsedInput hasPrefix:@"S"]) {
        if (multipleOptions) {
          [generatedPropertyString appendString:@", "];
        }
        
       [generatedPropertyString appendString:(NSString *)@"setter="];
       [generatedPropertyString appendString:(NSString *)[parsedInput substringFromIndex:1]];
       [blackListMethodNames addObject:[parsedInput substringFromIndex:1]];
        multipleOptions = 1;
      } else if ([parsedInput isEqualToString:@"&"]) {
        if (multipleOptions) {
          [generatedPropertyString appendString:@", "];
        }
        [generatedPropertyString appendString:@"strong"];
        multipleOptions = 1;
      } else if ([parsedInput hasPrefix:@"V"]) { // ivar name here, V_name
      } else if ([parsedInput hasPrefix:@"T"]) { // Type here, T@"NSString"
        if ( (BOOL)[[[parsedInput substringToIndex:2] substringFromIndex:1] isEqualToString: @"@"]) { // It's a NSObject
          
          NSString *tmpPropertyType = [parsedInput substringFromIndex:1];
          NSArray *propertyComponents = [tmpPropertyType componentsSeparatedByString:@"\""];
          if ([propertyComponents count] > 1) {
            NSString *component = (NSString *)[propertyComponents objectAtIndex:1];
            component = [component stringByReplacingOccurrencesOfString:@"><" withString:@", "];
            if ([component hasPrefix:@"<"]) {
              propertyType = (NSString *)[@"id" stringByAppendingString:component];
              NSString *formatted = [[component stringByReplacingOccurrencesOfString:@"<" withString:@""] stringByReplacingOccurrencesOfString:@">" withString:@""];
              for (NSString *f in [formatted componentsSeparatedByString:@", "]) {
                [exportedProtocolsSet addObject:f];
              }
            } else {
              [exportedClassesSet addObject:component];
              propertyType = (NSString *)[component stringByAppendingString:@"*"];
            }
          } else {

            propertyType = @"id";
          }
        } else {
          propertyType = argumentBlock([parsedInput substringFromIndex:1]);
        }
      }
    }
    [generatedPropertyString appendString:(NSString *)[(NSString *)[(NSString *)[(NSString *)[@") " stringByAppendingString:propertyType] stringByAppendingString:@" "] stringByAppendingString:name] stringByAppendingString:@";\n"]];

    [generatedProperties appendString:generatedPropertyString];
    [blackListMethodNames addObject:name];
  }
  NSMutableArray *tmpSetArray = [NSMutableArray array];
  for (NSString *propertyName in [blackListMethodNames allObjects]) {
    NSString *setter = (NSString *)[@"set" stringByAppendingString:(NSString *)[(NSString *)[(NSString *)[[propertyName substringToIndex:1] uppercaseString] stringByAppendingString:[propertyName substringFromIndex:1]] stringByAppendingString:@":"]];
    [tmpSetArray addObject:setter];
  }
 
  [blackListMethodNames addObjectsFromArray:tmpSetArray];
  NSString *(^generateMethodsForClass)(Class) = ^(Class cls) {
    
    NSMutableString* generatedMethods = [NSMutableString stringWithString:@""];
    unsigned int classCount = 0;
    Method *methods = (Method *)class_copyMethodList(cls, &classCount);
    NSString *classOrInstanceStart = (BOOL)class_isMetaClass(cls) ? @"+" : @"-";
    
    for (int i = 0; i < classCount; i++) {
      Method m = methods[i];
      NSString *methodName = NSStringFromSelector((SEL)method_getName(m));
      if ([blackListMethodNames containsObject:methodName]) {
        continue;
      }
      NSMutableString *generatedMethodString = [NSMutableString stringWithString:classOrInstanceStart];
      char *retType = (char *)method_copyReturnType(m);
      NSString *retTypeString = [NSString stringWithUTF8String:retType];
      free(retType);
      unsigned int arguments = (unsigned int)method_getNumberOfArguments(m);
      
      [generatedMethodString appendString:(NSString *)[(NSString *)[@"(" stringByAppendingString:argumentBlock(retTypeString)] stringByAppendingString:@")"]];
      NSArray *methodComponents = [methodName componentsSeparatedByString:@":"];
      
      NSMutableString *realizedMethod = [NSMutableString stringWithString:@""];
      for (int j = 2; j < arguments; j++) { // id, sel, always
        int index = j - 2;
        [realizedMethod appendString:(NSString *)[methodComponents[index] stringByAppendingString:@":"]];
        char *argumentType = (char *)method_copyArgumentType(m, j);
        NSString *argumentTypeString = [NSString stringWithUTF8String:argumentType];
        free(argumentType);
        [realizedMethod appendFormat:(NSString *)[(NSString *)[@"(" stringByAppendingString:argumentBlock(argumentTypeString)] stringByAppendingString:@")"]];
        
        [realizedMethod appendString:@"arg"];
        [realizedMethod appendString:[@(index) stringValue]];
        [realizedMethod appendString:@" "];
      }
      [generatedMethodString appendString:realizedMethod];
      if (arguments == 2) {
        [generatedMethodString appendString:methodName];
      }
      
      [generatedMethods appendString:(NSString *)[generatedMethodString stringByAppendingString:@";\n"]];
      
      
    }
    free(methods);
    return generatedMethods;
  };
  
  // Instance Methods
  NSString *generatedInstanceMethods = generateMethodsForClass((Class)cls);
  
  // Class Methods
  Class metaClass = (Class)objc_getMetaClass((char *)class_getName(cls));
  NSString *generatedClassMethods = generateMethodsForClass(metaClass);
  

  NSMutableString *finalString = [NSMutableString string];
  [finalString appendString:@"#import <Foundation/Foundation.h>\n\n"];
  if ([exportedClassesSet count] > 0) {
    NSMutableString *importString = [NSMutableString string];
    [importString appendString:@"@class "];
    for (NSString *str in [exportedClassesSet allObjects]) {
      [importString appendString:str];
      [importString appendString:@", "];
    }
    [importString appendString:@";"];
    NSString *finalImport = [importString stringByReplacingOccurrencesOfString:@", ;" withString:@";\n\n"];
    [finalString appendString:finalImport];
  }


    if ([exportedProtocolsSet count] > 0) {
    NSMutableString *importString = [NSMutableString string];
    [importString appendString:@"@protocol "];
    for (NSString *str in [exportedProtocolsSet allObjects]) {
      [importString appendString:str];
      [importString appendString:@", "];
    }
    [importString appendString:@";"];
    NSString *finalImport = [importString stringByReplacingOccurrencesOfString:@", ;" withString:@";\n\n"];
    [finalString appendString:finalImport];
  }'''

    if options.generate_protocol:
        script += r'''
  [finalString appendString:@"\n@protocol DS_"];
  [finalString appendString:(NSString *)[cls description]];
  [finalString appendString:@"Protocol <NSObject>"];'''
    else: 
        script += r'''
  [finalString appendString:@"\n@interface "];
  [finalString appendString:(NSString *)[cls description]];
  [finalString appendString:@" : "];
  [finalString appendString:(NSString *)[[cls superclass] description]];'''
  
    script += r'''
  [finalString appendString:@"\n\n"];
  [finalString appendString:generatedProperties];
  [finalString appendString:@"\n"];
  [finalString appendString:generatedClassMethods];
  [finalString appendString:generatedInstanceMethods];
  [finalString appendString:@"\n@end"];

  [returnString appendString:finalString];

  // Free stuff
  free(properties);
  returnString;
'''
    return script


def create_or_touch_filepath(filepath, contents):
    file = open(filepath, "w")
    file.write(contents)
    file.flush()
    file.close()

def generate_option_parser():
    usage = "usage: %prog [options] /optional/path/to/executable/or/bundle"
    parser = optparse.OptionParser(usage=usage, prog="dump_classes")

    parser.add_option("-f", "--filter",
                      action="store",
                      default=None,
                      dest="filter",
                      help="List all the classes in the module that are subclasses of class. -f UIView")

    parser.add_option("-m", "--module",
                      action="store",
                      default=None,
                      dest="module",
                      help="Filter class by module. You only need to give the module name and not fullpath")

    parser.add_option("-r", "--regular_expression",
                      action="store",
                      default=None,
                      dest="regular_expression",
                      help="Search the available classes using a regular expression search")

    parser.add_option("-v", "--verbose",
                      action="store_true",
                      default=False,
                      dest="verbose",
                      help="Enables verbose mode for dumping classes. Doesn't work w/ -g or -p")

    parser.add_option("-g", "--generate_header",
                      action="store_true",
                      default=False,
                      dest="generate_header",
                      help="Generate a header for the specified class. -h UIView")

    parser.add_option("-p", "--generate_protocol",
                      action="store_true",
                      default=False,
                      dest="generate_protocol",
                      help="Generate a protocol that you can cast to any object")

    parser.add_option("-c", "--conforms_to_protocol",
                      action="store",
                      default=None,
                      dest="conforms_to_protocol",
                      help="Only returns the classes that conforms to a particular protocol")
    return parser

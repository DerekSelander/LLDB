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
import ds
import os
import shlex
import optparse
import datetime
import lldb.utils.symbolication


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f dclass.dclass dclass -h "Dumps info about objc/swift classes"')


def dclass(debugger, command, exe_ctx, result, internal_dict):
    '''
    Dumps all the NSObject inherited classes in the process. If you give it a module, 
    it will dump only the classes within that module. You can also filter out classes 
    to only a certain type and can also generate a header file for a specific class.
  
  Example: 
  
      # Dump ALL the NSObject classes within the process
      (lldb) dclass 

      # Dump all the classes that are a UIViewController within the process
      (lldb) dclass -f UIViewController
      
      # Dump all the classes with the regex case insensitive search "viewcontroller" in the class name
      (lldb) dclass -r (?i)viewCoNtrolLer
      
      # Dump all the classes within the UIKit module
      (lldb) dclass -m UIKit

      # Dump all classes in CKConfettiEffect NSBundle that are UIView subclasses
      (lldb) dclass /System/Library/Messages/iMessageEffects/CKConfettiEffect.bundle/CKConfettiEffect -f UIView
      
      # Generate a header file for the class specified:
      (lldb) dclass -g UIView
      
      # Generate a protocol that you can cast an object to. Ideal when working with private classes at dev time
      (lldb) dclass -P UIView

      # Dump all classes and methods for a particular module, ideal for viewing changes in frameworks over time
      (lldb) dclass -o UIKit

      # Only dump classes whose superclass is of type class and in UIKit module. Ideal for going after specific classes
      (lldb) dclass -s NSObject -m UIKit
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
    target = exe_ctx.target

    if not options.info and not options.class_type and not options.verbose and not options.regular_expression and not options.module and not options.filter and not options.search_protocols and not options.dump_code_output and not options.generate_header and not options.verbose_info and not options.generate_protocol and not options.conforms_to_protocol and not options.superclass and len(args) == 1:
        options.info = args[0]

    if options.info or options.verbose_info:
        script = generate_class_info(options)

        # print(script)
        # return
        interpreter.HandleCommand('expression -lobjc -O -- ' + script, res)
        if res.GetError():
            result.SetError(res.GetError()) 
            return
        contents = res.GetOutput()
        result.AppendMessage(contents)
        return




    elif options.dump_code_output:
        directory = '/tmp/{}_{}/'.format(target.executable.basename, datetime.datetime.now().time())
        os.makedirs(directory)

        modules = target.modules
        if len(args) > 0 and args[0] == '__all':
            os.makedirs(directory + 'PrivateFrameworks')
            os.makedirs(directory + 'Frameworks')
            modules = [i for i in target.modules if '/usr/lib/' not in i.file.fullpath and '__lldb_' not in i.file.fullpath]
            outputMsg = "Dumping all private Objective-C frameworks"
        elif len(args) > 0 and args[0]:
            module = target.module[args[0]]
            if module is None:
                result.SetError( "Unable to open module name '{}', to see list of images use 'image list -b'".format(args[0]))
                return
            modules = [module]
            outputMsg = "Dumping all private Objective-C frameworks"
        else:
            modules = [target.module[target.executable.fullpath]]

        for module in modules:
            command_script = generate_module_header_script(options, module.file.fullpath.replace('//', '/'))

            interpreter.HandleCommand('expression -lobjc -O -u0 -- ' + command_script, res)
            # debugger.HandleCommand('expression -lobjc -O -- ' + command_script)
            if '/System/Library/PrivateFrameworks/' in module.file.fullpath:
                subdir = 'PrivateFrameworks/'
            elif '/System/Library/Frameworks/' in module.file.fullpath:
                subdir = 'Frameworks/'
            else:
                subdir = ''

            ds.create_or_touch_filepath(directory + subdir + module.file.basename + '.txt', res.GetOutput())
        print('Written output to: ' + directory + '... opening file')
        os.system('open -R ' + directory)
        return

    if options.module is not None:
        module = target.FindModule(lldb.SBFileSpec(options.module))
        if not module.IsValid():
            result.SetError(
                "Unable to open module name '{}', to see list of images use 'image list -b'".format(str(options.module)))
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
        command_script = generate_class_dump(target, options, clean_command)

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

        ds.create_or_touch_filepath(filepath, contents)
        print('Written output to: ' + filepath + '... opening file')
        os.system('open -R ' + filepath)
    else: 
        msg = "Dumping protocols" if options.search_protocols else "Dumping classes"
        result.AppendMessage(ds.attrStr(msg, 'cyan'))

        interpreter.HandleCommand('expression -lobjc -O -- ' + command_script, res)
        # debugger.HandleCommand('expression -lobjc -O -g -- ' + command_script)
        if res.GetError():
            result.SetError(ds.attrStr(res.GetError(), 'red'))
            return
        result.AppendMessage(ds.attrStr('************************************************************', 'cyan'))
        if res.Succeeded(): 
            result.AppendMessage(res.GetOutput())


def generate_class_dump(target, options, clean_command=None):
    command_script = r'''
  @import ObjectiveC;
  @import Foundation;
  unsigned int count = 0;

  typedef struct ds_cls_struct {
    void *isa;
    void *supercls;
    void *buckets;
    uint32_t _mask;
    uint32_t _occupied;
    uintptr_t bits;
  } ds_cls_struct;

  '''
    if options.search_protocols:
        command_script += 'Protocol **allProtocols = objc_copyProtocolList(&count);\n'
    elif clean_command:
        command_script += '  const char **allClasses = objc_copyClassNamesForImage("' + clean_command + '", &count);'
    else:
        command_script += 'Class *allClasses = objc_copyClassList(&count);\n'

    if options.regular_expression is not None: 
        command_script += '  NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"' + options.regular_expression + '" options:0 error:nil];\n'

    if options.search_protocols:
        command_script += '''  NSMutableString *classesString = [NSMutableString string];
  for (int i = 0; i < count; i++) {
    Protocol *ptl =  allProtocols[i];
        '''
    else: 
        command_script += '''  NSMutableString *classesString = [NSMutableString string];
      for (int i = 0; i < count; i++) {
        Class cls =  '''
        command_script += 'objc_getClass(allClasses[i]);' if clean_command else 'allClasses[i];'

    if options.module is not None: 
        command_script += generate_module_search_sections_string(options.module, target, options.search_protocols)

    if not options.search_protocols and options.conforms_to_protocol is not None:
      command_script +=  'if (!class_conformsToProtocol(cls, NSProtocolFromString(@"'+ options.conforms_to_protocol + '"))) { continue; }'
  

    if options.search_protocols:
        command_script += '  NSString *clsString = (NSString *)NSStringFromProtocol(ptl);\n'
    else:
        command_script += '  NSString *clsString = (NSString *)NSStringFromClass(cls);\n'
    if options.regular_expression is not None:
        command_script += r'''
    NSUInteger matches = (NSUInteger)[regex numberOfMatchesInString:clsString options:0 range:NSMakeRange(0, [clsString length])];
    if (matches == 0) {
      continue;
    }
        '''
    if options.class_type == 'objc':
        command_script += ' if ((((ds_cls_struct *)cls)->bits & 1UL) == 1) { continue; }\n'
    if options.class_type == 'swift':
        command_script += 'if ((((ds_cls_struct *)cls)->bits & 1UL) == 0) { continue; }\n'

    if not options.search_protocols and options.superclass is not None:

        command_script += 'NSString *parentClassName = @"' + options.superclass + '";'
        command_script += r'''
        if (!(BOOL)[NSStringFromClass((Class)[cls superclass]) isEqualToString:parentClassName]) { 
          continue; 
        }
          '''

    if not options.search_protocols and options.filter is None:
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

        '''
        command_script += '\n  free(allClasses);\n  [classesString description];'
    elif not options.search_protocols:
        command_script += '\n    if ((BOOL)[cls respondsToSelector:@selector(isSubclassOfClass:)] && (BOOL)[cls isSubclassOfClass:(Class)NSClassFromString(@"' + str(options.filter) + '")]) {\n'    
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


    else:
        command_script += r'''
        [classesString appendString:(NSString *)clsString];
        [classesString appendString:@"\n"];

          }'''
        command_script += '\n  free(allProtocols);\n  [classesString description];'
    return command_script

def generate_module_search_sections_string(module_name, target, useProtocol=False):
    module = target.FindModule(lldb.SBFileSpec(module_name))
    if not module.IsValid():
        result.SetError(
            "Unable to open module name '{}', to see list of images use 'image list -b'".format(module_name))
        return

    if useProtocol:
        returnString = r'''
        uintptr_t addr = (uintptr_t)ptl;
        if (!('''
    else:
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
  // typedef struct objc_category *Category;
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
      NSString *methodName = NSStringFromSelector((char *)method_getName(m));
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
        [realizedMethod appendString:(NSString *)[(NSString *)[@"(" stringByAppendingString:argumentBlock(argumentTypeString)] stringByAppendingString:@")"]];
        
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

def generate_module_header_script(options, modulePath):
    script = r'''@import @ObjectiveC;
  //Dang it. LLDB JIT Doesn't like NSString stringWithFormat on device. Need to use stringByAppendingString instead

  // Runtime declarations in case we're running on a stripped executable
  typedef struct objc_method *Method;
  typedef struct objc_ivar *Ivar;
  // typedef struct objc_category *Category;
  typedef struct objc_property *objc_property_t;

  NSMutableString *returnString = [NSMutableString string];

  [returnString appendString:@"''' + modulePath + r'''\n************************************************************\n"];
  // Properties
  NSMutableSet *exportedClassesSet = [NSMutableSet set];
  NSMutableSet *exportedProtocolsSet = [NSMutableSet set];
  
  unsigned int count = 0;
  const char **allClasses = (const char **)objc_copyClassNamesForImage("''' + modulePath + r'''", &count);
  NSMutableDictionary *returnDict = [NSMutableDictionary dictionaryWithCapacity:count];

  for (int i = 0; i < count; i++) {
    Class cls = objc_getClass(allClasses[i]);

    NSMutableString *generatedProperties = [NSMutableString string];
    NSMutableSet *blackListMethodNames = [NSMutableSet set];
    [blackListMethodNames addObjectsFromArray:@[@".cxx_destruct", @"dealloc"]];

    unsigned int propertyCount = 0;
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
        NSString *methodName = NSStringFromSelector((char *)method_getName(m));
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
          [realizedMethod appendString:(NSString *)[(NSString *)[@"(" stringByAppendingString:argumentBlock(argumentTypeString)] stringByAppendingString:@")"]];
          
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


  [finalString appendString:(NSString *)[cls description]];
  [finalString appendString:@" : "];
  [finalString appendString:(NSString *)[[cls superclass] description]];
  [finalString appendString:(NSString *)[[[generatedProperties componentsSeparatedByString:@"\n"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"\n "]];
  [finalString appendString:(NSString *)[[[[generatedClassMethods stringByReplacingOccurrencesOfString:@" ;" withString:@";"] componentsSeparatedByString:@"\n"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"\n "]];
  [finalString appendString:(NSString *)[[[[generatedInstanceMethods stringByReplacingOccurrencesOfString:@" ;" withString:@";"] componentsSeparatedByString:@"\n"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"\n "]];
  [finalString appendString:@"\n************************************************************\n"];

  [returnDict setObject:(id _Nonnull)finalString forKey:(id _Nonnull)[cls description]];
  // Free stuff
  free(properties);
  } 

  NSArray *sortedKeys = [[returnDict allKeys] sortedArrayUsingSelector: @selector(compare:)];
  NSMutableArray *sortedValues = [NSMutableArray array];
  for (NSString *key in sortedKeys) {
    [returnString appendString:(NSString *)[returnDict objectForKey:key]];
  }
  returnString; 
'''
    return script

def generate_class_info(options):
    if options.verbose_info and not options.info:
        options.info = options.verbose_info
        verboseOutput = True
    else:
        verboseOutput = False

    if '.' in options.info:
        classInfo = "(Class)NSClassFromString(@\"" + options.info + "\")"
    else:
        classInfo = "[" + options.info + " class]"


    script = "BOOL verboseOutput = {};\n".format("YES" if verboseOutput else "NO")
    script +=  r'''
    @import Foundation;
    @import ObjectiveC;

    #define RO_META               (1<<0)
  // class is a root class
#define RO_ROOT               (1<<1)
  // class has .cxx_construct/destruct implementations
#define RO_HAS_CXX_STRUCTORS  (1<<2)
  // class has +load implementation
  // #define RO_HAS_LOAD_METHOD    (1<<3)
  // class has visibility=hidden set
#define RO_HIDDEN             (1<<4)
  // class has attribute(objc_exception): OBJC_EHTYPE_$_ThisClass is non-weak
#define RO_EXCEPTION          (1<<5)
  // this bit is available for reassignment
  // #define RO_REUSE_ME           (1<<6)
  // class compiled with ARC
#define RO_IS_ARC             (1<<7)
  // class has .cxx_destruct but no .cxx_construct (with RO_HAS_CXX_STRUCTORS)
#define RO_HAS_CXX_DTOR_ONLY  (1<<8)
  // class is not ARC but has ARC-style weak ivar layout
#define RO_HAS_WEAK_WITHOUT_ARC (1<<9)
  
  // class is in an unloadable bundle - must never be set by compiler
#define RO_FROM_BUNDLE        (1<<29)
  // class is unrealized future class - must never be set by compiler
#define RO_FUTURE             (1<<30)
  // class is realized - must never be set by compiler
#define RO_REALIZED           (1<<31)
  
  // Values for class_rw_t->flags
  // These are not emitted by the compiler and are never used in class_ro_t.
  // Their presence should be considered in future ABI versions.
  // class_t->data is class_rw_t, not class_ro_t
#define RW_REALIZED           (1<<31)
  // class is unresolved future class
#define RW_FUTURE             (1<<30)
  // class is initialized
#define RW_INITIALIZED        (1<<29)
  // class is initializing
#define RW_INITIALIZING       (1<<28)
  // class_rw_t->ro is heap copy of class_ro_t
#define RW_COPIED_RO          (1<<27)
  // class allocated but not yet registered
#define RW_CONSTRUCTING       (1<<26)
  // class allocated and registered
#define RW_CONSTRUCTED        (1<<25)
  // available for use; was RW_FINALIZE_ON_MAIN_THREAD
  // #define RW_24 (1<<24)
  // class +load has been called
#define RW_LOADED             (1<<23)
#if !SUPPORT_NONPOINTER_ISA
  // class instances may have associative references
#define RW_INSTANCES_HAVE_ASSOCIATED_OBJECTS (1<<22)
#endif
  // class has instance-specific GC layout
#define RW_HAS_INSTANCE_SPECIFIC_LAYOUT (1 << 21)
  // available for use
  // #define RW_20       (1<<20)
  // class has started realizing but not yet completed it
#define RW_REALIZING          (1<<19)
  
  // NOTE: MORE RW_ FLAGS DEFINED BELOW
  
  
  // Values for class_rw_t->flags or class_t->bits
  // These flags are optimized for retain/release and alloc/dealloc
  // 64-bit stores more of them in class_t->bits to reduce pointer indirection.
  
#if !__LP64__
  
  // class or superclass has .cxx_construct implementation
#define RW_HAS_CXX_CTOR       (1<<18)
  // class or superclass has .cxx_destruct implementation
#define RW_HAS_CXX_DTOR       (1<<17)
  // class or superclass has default alloc/allocWithZone: implementation
  // Note this is is stored in the metaclass.
#define RW_HAS_DEFAULT_AWZ    (1<<16)
  // class's instances requires raw isa
#if SUPPORT_NONPOINTER_ISA
#define RW_REQUIRES_RAW_ISA   (1<<15)
#endif
  
  // class is a Swift class
#define FAST_IS_SWIFT         (1UL<<0)
  // class or superclass has default retain/release/autorelease/retainCount/
  //   _tryRetain/_isDeallocating/retainWeakReference/allowsWeakReference
#define FAST_HAS_DEFAULT_RR   (1UL<<1)
  // data pointer
#define FAST_DATA_MASK        0xfffffffcUL
  
#elif 1
  // Leaks-compatible version that steals low bits only.
  
  // class or superclass has .cxx_construct implementation
#define RW_HAS_CXX_CTOR       (1<<18)
  // class or superclass has .cxx_destruct implementation
#define RW_HAS_CXX_DTOR       (1<<17)
  // class or superclass has default alloc/allocWithZone: implementation
  // Note this is is stored in the metaclass.
#define RW_HAS_DEFAULT_AWZ    (1<<16)
  
  // class is a Swift class
#define FAST_IS_SWIFT           (1UL<<0)
  // class or superclass has default retain/release/autorelease/retainCount/
  //   _tryRetain/_isDeallocating/retainWeakReference/allowsWeakReference
#define FAST_HAS_DEFAULT_RR     (1UL<<1)
  // class's instances requires raw isa
#define FAST_REQUIRES_RAW_ISA   (1UL<<2)
  // data pointer
#define FAST_DATA_MASK          0x00007ffffffffff8UL
  
#else
  // Leaks-incompatible version that steals lots of bits.
  
  // class is a Swift class
#define FAST_IS_SWIFT           (1UL<<0)
  // class's instances requires raw isa
#define FAST_REQUIRES_RAW_ISA   (1UL<<1)
  // class or superclass has .cxx_destruct implementation
  //   This bit is aligned with isa_t->hasCxxDtor to save an instruction.
#define FAST_HAS_CXX_DTOR       (1UL<<2)
  // data pointer
#define FAST_DATA_MASK          0x00007ffffffffff8UL
  // class or superclass has .cxx_construct implementation
#define FAST_HAS_CXX_CTOR       (1UL<<47)
  // class or superclass has default alloc/allocWithZone: implementation
  // Note this is is stored in the metaclass.
#define FAST_HAS_DEFAULT_AWZ    (1UL<<48)
  // class or superclass has default retain/release/autorelease/retainCount/
  //   _tryRetain/_isDeallocating/retainWeakReference/allowsWeakReference
#define FAST_HAS_DEFAULT_RR     (1UL<<49)
  // summary bit for fast alloc path: !hasCxxCtor and
  //   !instancesRequireRawIsa and instanceSize fits into shiftedSize
#define FAST_ALLOC              (1UL<<50)
  // instance size in units of 16 bytes
  //   or 0 if the instance size is too big in this field
  //   This field must be LAST
#define FAST_SHIFTED_SIZE_SHIFT 51
  
  // FAST_ALLOC means
  //   FAST_HAS_CXX_CTOR is set
  //   FAST_REQUIRES_RAW_ISA is not set
  //   FAST_SHIFTED_SIZE is not zero
  // FAST_ALLOC does NOT check FAST_HAS_DEFAULT_AWZ because that
  // bit is stored on the metaclass.
#define FAST_ALLOC_MASK  (FAST_HAS_CXX_CTOR | FAST_REQUIRES_RAW_ISA)
#define FAST_ALLOC_VALUE (0)
  
#endif
  
typedef struct dsdl_info {
        const char      *dli_fname;     /* Pathname of shared object */
        void            *dli_fbase;     /* Base address of shared object */
        const char      *dli_sname;     /* Name of nearest symbol */
        void            *dli_saddr;     /* Address of nearest symbol */
} dsDl_info;


//*****************************************************************************/
#pragma mark - Methods
//*****************************************************************************/
  
typedef struct method_t {
    char * name;
    const char *types;
    IMP imp;
} method_t;
  
typedef struct method_list_t {
    uint32_t entsizeAndFlags;
    uint32_t count;
    method_t *first;
} method_list_t;
  
  
typedef  struct  method_array_t {
    uint32_t count;
    method_list_t *methods;
} method_array_t;
  
  
//*****************************************************************************/
#pragma mark - Ivars
//*****************************************************************************/
  
typedef struct ivar_t {
#if __x86_64__
    // *offset was originally 64-bit on some x86_64 platforms.
    // We read and write only 32 bits of it.
    // Some metadata provides all 64 bits. This is harmless for unsigned
    // little-endian values.
    // Some code uses all 64 bits. class_addIvar() over-allocates the
    // offset for their benefit.
#endif
    int32_t *offset;
    const char *name;
    const char *type;
    // alignment is sometimes -1; use alignment() instead
    uint32_t alignment_raw;
    uint32_t size;
    
  } ivar_t;
  
  
typedef struct ivar_list_t {
    uint32_t entsizeAndFlags;
    uint32_t count;
    ivar_t *first;
} ivar_list_t;
  
//*****************************************************************************/
#pragma mark - Properties
//*****************************************************************************/
typedef struct property_t {
    const char *name;
    const char *attributes;
} property_t;

  
typedef struct property_list_t {
    uint32_t entsizeAndFlags;
    uint32_t count;
    property_t *first;
} property_list_t;

  
typedef  struct  property_array_t {
    uint32_t count;
    property_list_t *properties;
} property_array_t;

//*****************************************************************************/
#pragma mark - Protocols
//*****************************************************************************/
  
 typedef struct dsprotocol_t  {

    uint32_t flags;
    uint32_t version;
    const char *name;
//    struct protocol_list_t *protocols;
//    method_list_t *instanceMethods;
//    method_list_t *classMethods;
//    method_list_t *optionalInstanceMethods;
//    method_list_t *optionalClassMethods;
//    property_list_t *instanceProperties;
//    uint32_t size;   // sizeof(protocol_t)
//    uint32_t flags;
//    // Fields below this point are not always present on disk.
//    const char **_extendedMethodTypes;
//    const char *_demangledName;
//    property_list_t *_classProperties;

} dsprotocol_t;


typedef struct protocol_list_t {
    uintptr_t count;
    dsprotocol_t *first;
} protocol_list_t;
  
typedef  struct  protocol_array_t {
    uint32_t count;
    protocol_list_t *protocols;
} protocol_array_t;
  
//*****************************************************************************/
#pragma mark - Categories
//*****************************************************************************/

typedef struct class_ro_t {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
#ifdef __LP64__
    uint32_t reserved;
#endif
    
    const uint8_t * ivarLayout;
    
    const char * name;
    method_list_t * baseMethodList;
    protocol_list_t * baseProtocols;
    ivar_list_t * ivars;
    uint8_t * weakIvarLayout;
    property_list_t *baseProperties;
  
} class_ro_t;
  
  
typedef struct class_rw_t {
    uint32_t flags;
    uint32_t version;
    
    const class_ro_t *ro;
    
    method_array_t methods;        // redefined from method_array_t
    property_array_t properties;   // redefined from property_array_t
    protocol_list_t protocols;    // redefined from protocol_array_t
  
    struct dsobjc_class*   firstSubclass;
    struct dsobjc_class* nextSiblingClass;
    
    char *demangledName;
    
} class_rw_t;
  
  typedef struct dsobjc_class {
    struct dsobjc_class* isa;
    struct dsobjc_class* superclass;
    void *_buckets;             // formerly cache pointer and vtable
    uint32_t _mask;
    uint32_t _occupied;
    uintptr_t bits;
    
    class_rw_t *ds_data() {
      return (class_rw_t *)(bits & FAST_DATA_MASK);
    }
    
  } dsobjc_class;


  typedef struct dsswift_class {
    struct dsobjc_class *isa;
    struct dsobjc_class *superclass;
    void *_buckets;
    void *maskAndOccupied;
    uintptr_t bits;
    uint32_t flags;
    uint32_t instanceAddressPoint;
    uint32_t instanceSize;
    uint16_t instanceAlignMask;
    uint16_t runtimeReservedBits;
    uint32_t classSize;
    uint32_t classAddressPoint;
    uintptr_t typeDescriptor;
    uintptr_t ivarDestroyer;
    uintptr_t *methods;

    class_rw_t *ds_data() {
      return (class_rw_t *)(bits & FAST_DATA_MASK);
    }
    
  } dsswift_class;
  


  dsobjc_class *dsclass = (dsobjc_class*)''' + classInfo + r''';
  uint32_t roflags = dsclass->ds_data()->ro->flags;
  uint32_t rwflags = dsclass->ds_data()->flags;
  const char* name = dsclass->ds_data()->ro->name;
  const char* superclassName = dsclass->superclass ? dsclass->superclass->ds_data()->ro->name : nil;
  property_list_t *bprops = dsclass->ds_data()->ro->baseProperties;
  protocol_list_t *bprot = dsclass->ds_data()->ro->baseProtocols;
  method_list_t *bmeth = dsclass->ds_data()->ro->baseMethodList;
  ivar_list_t *bivar = dsclass->ds_data()->ro->ivars;  

  NSMutableString *returnString = [NSMutableString new];

  if (verboseOutput) {
  [returnString appendString:@"\n******************************************\n"];
  [returnString appendString:@"  "];
  [returnString appendString:[NSString stringWithUTF8String:(char *)name]];
  if (superclassName && (roflags & RO_META)) {

    [returnString appendString:@" : (META)"];
  } else if (superclassName) {
    [returnString appendString:@" : "];
    [returnString appendString:[NSString stringWithUTF8String:(char *)superclassName]];
  }

   [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@" (%p)", dsclass]];
  [returnString appendString:@"\n******************************************\n\n"];


  [returnString appendString:@"Found in: "];
  [returnString appendString:[NSString stringWithUTF8String:(char *)class_getImageName((Class)dsclass)]];
  [returnString appendString:@"\n\n"];

  [returnString appendString:@"Swift:\t\t\t"];
  [returnString appendString:dsclass->bits & FAST_IS_SWIFT ? @"YES\n" : @"NO\n" ];

  [returnString appendString:@"Size:\t\t\t"];
  [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"0x%x bytes", dsclass->ds_data()->ro->instanceSize]];

  [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"\nInstance Start:\t0x%x", dsclass->ds_data()->ro->instanceStart]];

  [returnString appendString:@"\nMeta:\t\t\t"];
  [returnString appendString:(BOOL)class_isMetaClass((Class)dsclass) ? @"YES" : @"NO"];;
  [returnString appendString:@"\n\n"];

  ///////////////////////////////////////////////////////////////////
  [returnString appendString:@"Protocols: "];
  [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"\t\t%d\t%p\n",  bprot ? bprot->count : 0, bprot ? &bprot->first : 0]];

  [returnString appendString:@"Ivars: "];
  [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"\t\t\t%d\t%p\n",  bivar ? bivar->count : 0, bivar ? &bivar->first : 0]];

  [returnString appendString:@"Properties: "];
  [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"\t%d\t%p\n", bprops ? bprops->count : 0, bprops ? &bprops->first : 0]];

  if (!(roflags & RO_META)) {
    [returnString appendString:@"I ObjC Meth: "];
  } else {
    [returnString appendString:@"C ObjC Meth: "];
  }
  [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"\t%d\t%p\n", bmeth ? bmeth->count : 0, bmeth ? &bmeth->first : 0]];

  if (!(roflags & RO_META) && NSClassFromString(@"UIView")) { // Cocoa's isa layout is different?
    method_list_t *classmeth = dsclass->isa->ds_data()->ro->baseMethodList;
    [returnString appendString:@"C ObjC Meth: "];
    [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"\t%d\t%p\n", classmeth ? classmeth->count : 0, classmeth ? &classmeth->first : 0]];
  }

  ///////////////////////////////////////////////////////////////////
  [returnString appendString:@"\nRW Flags:\n"];

  [returnString appendString:@" "];
  [returnString appendString:(rwflags & RW_REALIZED) ? @"1" : @"0"];
  [returnString appendString:@"\tRW_REALIZED\t\t\tclass is realized\n"];

  [returnString appendString:@" "];
  [returnString appendString:(rwflags & RW_FUTURE) ? @"1" : @"0"];
  [returnString appendString:@"\tRW_FUTURE\t\t\tclass is unresolved future class\n"];

  [returnString appendString:@" "];
  [returnString appendString:(rwflags & RW_INITIALIZED) ? @"1" : @"0"];
  [returnString appendString:@"\tRW_INITIALIZED\t\tclass is initialized\n"];

  [returnString appendString:@" "];
  [returnString appendString:(rwflags & RW_INITIALIZING) ? @"1" : @"0"];
  [returnString appendString:@"\tRW_INITIALIZING\t\tclass is initializing\n"];

  [returnString appendString:@" "];
  [returnString appendString:(rwflags & RW_COPIED_RO) ? @"1" : @"0"];
  [returnString appendString:@"\tRW_COPIED_RO\t\tclass_rw_t->ro is heap copy of class_ro_t\n"];

  [returnString appendString:@" "];
  [returnString appendString:(rwflags & RW_CONSTRUCTING) ? @"1" : @"0"];
  [returnString appendString:@"\tRW_CONSTRUCTING\t\tclass allocated but not yet registered\n"];

  [returnString appendString:@" "];
  [returnString appendString:(rwflags & RW_CONSTRUCTED) ? @"1" : @"0"];
  [returnString appendString:@"\tRW_CONSTRUCTED\t\tclass allocated and registered\n"];

  [returnString appendString:@" "];
  [returnString appendString:(rwflags & RW_LOADED) ? @"1" : @"0"];
  [returnString appendString:@"\tRW_LOADED\t\t\tclass +load has been called\n"];

  /////////////////////////////////////////////////////////////////////

  [returnString appendString:@"\nRO Flags:\n"];
  [returnString appendString:@" "];
  [returnString appendString:(roflags & RO_META) ? @"1" : @"0"];
  [returnString appendString:@"\tRO_META\t\t\t\tclass is a metaclass\n"];

  [returnString appendString:@" "];
  [returnString appendString: roflags & RO_ROOT ? @"1" : @"0"];
  [returnString appendString:@"\tRO_ROOT\t\t\t\tclass is a root class\n"];

  [returnString appendString:@" "];
  [returnString appendString: roflags & RO_HAS_CXX_STRUCTORS ? @"1" : @"0"];
  [returnString appendString:@"\tRO_HAS_CXX_STRUCTORS\tclass has .cxx_construct/destruct implementations\n"];

  [returnString appendString:@" "];
  [returnString appendString: roflags & RO_HIDDEN ? @"1": @"0"];
  [returnString appendString:@"\tRO_HIDDEN\t\t\t\tclass has visibility=hidden set\n"];

  [returnString appendString:@" "];
  [returnString appendString:roflags & RO_EXCEPTION ? @"1" : @"0"];
  [returnString appendString:@"\tRO_EXCEPTION\t\t\tclass has attribute(objc_exception): OBJC_EHTYPE_$_ThisClass is non-weak\n"];

  [returnString appendString:@" "];
  [returnString appendString:roflags & RO_IS_ARC ? @"1" : @"0"];
  [returnString appendString:@"\tRO_IS_ARC\t\t\t\tclass compiled with ARC\n"];

  [returnString appendString:@" "];
  [returnString appendString:roflags & RO_HAS_CXX_DTOR_ONLY ? @"1" : @"0"];
  [returnString appendString:@"\tRO_HAS_CXX_DTOR_ONLY\tclass has .cxx_destruct but no .cxx_construct (with RO_HAS_CXX_STRUCTORS)\n"];

  [returnString appendString:@" "];
  [returnString appendString:roflags & RO_HAS_WEAK_WITHOUT_ARC ? @"1" : @"0"];
  [returnString appendString:@"\tRO_HAS_WEAK_WITHOUT_ARC\tclass is not ARC but has ARC-style weak ivar layout\n"];

  [returnString appendString:@" "];
  [returnString appendString:roflags & RO_FROM_BUNDLE ? @"1" : @"0"];
  [returnString appendString:@"\tRO_FROM_BUNDLE\t\tclass is in an unloadable bundle - must never be set by compiler\n"];

  [returnString appendString:@" "];
  [returnString appendFormat:roflags & RO_FUTURE ? @"1" : @"0"];
  [returnString appendFormat:@"\tRO_FUTURE\t\t\tclass is unrealized future class - must never be set by compiler\n"];

  [returnString appendString:@" "];
  [returnString appendFormat:roflags & RO_REALIZED ? @"1" : @"0"];
  [returnString appendFormat:@"\tRO_REALIZED\t\t\tclass is realized - must never be set by compiler\n"];
}
  [returnString appendFormat:@"\n@interface "];

  [returnString appendString:[NSString stringWithUTF8String:(char *)name]];
  [returnString appendString:@" : "];
  if (superclassName) {
    [returnString appendString:[NSString stringWithUTF8String:(char *)superclassName]];
  }
  
  if (bprot) {
    [returnString appendString:@" <"];
    for (int i = 0; i < bprot->count; i++) {
      dsprotocol_t **pp = (&bprot->first);
      [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"%s", pp[i]->name]];
 
      if (i < (bprot->count - 1)) {
        [returnString appendString:@", "];
      }
    }
    [returnString appendString:@">"];
    
  }
  [returnString appendString:@"\n{\n"];

  if (bivar) {
    for (int i = 0; i < bivar->count; i++) {
      ivar_t *dsiv = (ivar_t *)(&bivar->first);
      [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@" %20s %-30s; offset 0x%x\n", (char *)dsiv[i].type, (char *)dsiv[i].name, *(int32_t *)dsiv[i].offset]];
    }
  }

  [returnString appendString:@"}\n\n"];

  if (bprops) {
    for (int i = 0; i < bprops->count; i++) {
      property_t *dsiv = (property_t *)(&bprops->first);
      [returnString appendString:@"@property "];
      [returnString appendString:[NSString stringWithUTF8String:(char *)dsiv[i].attributes]];
      [returnString appendString:@" *"];
      [returnString appendString:[NSString stringWithUTF8String:(char *)dsiv[i].name]];
      [returnString appendString:@"\n"];
    }
  }

  [returnString appendString:@"\n"];

  if (bmeth) {
    for (int i = 0; i < bmeth->count; i++) {
      NSString *methodType = (BOOL)class_isMetaClass((Class)dsclass) ? @"+" : @"-";
      method_t *mt = (method_t*)(&bmeth->first);
        // [returnString appendString:[NSString stringWithUTF8String:(char *)mt[i].types]];
        //[returnString appendString:[NSString stringWithUTF8String:(char *)mt[i].name]];
        [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@" %s%40s  %p\n", [methodType UTF8String], mt[i].name, mt[i].imp]];
    }
  }

  if (!(roflags & RO_META) && NSClassFromString(@"UIView")) { // Cocoa's isa is different? TODO
    method_list_t *classmeth = dsclass->isa->ds_data()->ro->baseMethodList;
    if (classmeth) {
      for (int i = 0; i < classmeth->count; i++) {
        NSString *methodType = (BOOL)class_isMetaClass((Class)dsclass->isa) ? @"+" : @"-";
        method_t *mt = (method_t*)(&classmeth->first);
        [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@" %s%40s  %p\n", [methodType UTF8String], mt[i].name, mt[i].imp]];
      }
    }
  }


  if (dsclass->bits & FAST_IS_SWIFT) {
    dsswift_class *dsswiftcls = (dsswift_class*)dsclass;
    unsigned long methodsAddress = (unsigned long)&dsswiftcls->methods;
    unsigned long endAddress = (unsigned long)dsswiftcls + dsswiftcls->classSize - dsswiftcls->classAddressPoint;
    int methodCount = ((int)(endAddress - methodsAddress)) / sizeof(uintptr_t*);

    [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"Swift methods: %d\n", methodCount]];
    for (int i = 0; i < methodCount; i++) {
      uintptr_t * ptr = (uintptr_t*)methodsAddress;
      dsDl_info dsinfo = {};
      dladdr((void*)ptr[i], &dsinfo);
      [returnString appendString:(NSString*)[[NSString alloc] initWithFormat:@"(%p) %s\n",  ptr[i], dsinfo.dli_sname]];
    }

  }

  [returnString appendString:@"\n"];
  [returnString appendString:@"@end\n"];
  
  
  returnString;
    '''
    return script



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

    parser.add_option("-t", "--class_type",
                      action="store",
                      default=None,
                      dest="class_type",
                      help="Specifies the class type, only supports \"objc\" or \"swift\"")

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

    parser.add_option("-P", "--generate_protocol",
                      action="store_true",
                      default=False,
                      dest="generate_protocol",
                      help="Generate a protocol that you can cast to any object")

    parser.add_option("-o", "--dump_code_output",
                      action="store_true",
                      default=False,
                      dest="dump_code_output",
                      help="Dump all classes and code per module, use \"__all\" to dump all ObjC modules known to proc")

    parser.add_option("-l", "--search_protocols",
                      action="store_true",
                      default=False,
                      dest="search_protocols",
                      help="Search for protocols instead of ObjC classes")

    parser.add_option("-p", "--conforms_to_protocol",
                      action="store",
                      default=None,
                      dest="conforms_to_protocol",
                      help="Only returns the classes that conforms to a particular protocol")

    parser.add_option("-s", "--superclass",
                      action="store",
                      default=None,
                      dest="superclass",
                      help="Returns only if the parent class is of type")

    parser.add_option("-i", "--info",
                      action="store",
                      default=None,
                      dest="info",
                      help="Get the info about a Objectie-C class, i.e. dclass -i UIViewController")

    parser.add_option("-I", "--verbose_info",
                      action="store",
                      default=None,
                      dest="verbose_info",
                      help="Get the info about a Objectie-C class, i.e. dclass -i UIViewController")
    return parser

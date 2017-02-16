

import lldb
import os
import shlex
import optparse
import lldb.utils.symbolication


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f dump_classes.dump_classes dclass')


def dump_classes(debugger, command, result, internal_dict):
    '''
    Dumps all the NSObject inherited classes in the process. If you give it a 
    module that exists on disk, it will dump only the classes within that module. 
    You can also filter out classes to only a certain type and can also generate 
    a header file for a specific class.

Examples:

    # Dump ALL the NSObject classes within the process
    (lldb) dclass 

    # Dump all the classes that are a UIViewController within the process
    (lldb) dclass -f UIViewController

    # Dump all classes in CKConfettiEffect NSBundle that are UIView subclasses
    (lldb) dclass /System/Library/Messages/iMessageEffects/CKConfettiEffect.bundle/CKConfettiEffect -f UIView

    # Generate a header file for the class specified:
    (lldb) dclass -g UIView

    # Generate a protocol that you can cast an object to. Ideal when working with private classes at dev time
    (lldb) dclass -p UIView

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
    if not args and options.generate_header:
        result.SetError('Need to supply class for option')
        return
    else:
        clean_command = ('').join(args)

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    if options.generate_header or options.generate_protocol:
        command_script = generate_header_script(options, clean_command)
    else:
        command_script = generate_class_dump(options, clean_command)

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
        interpreter.HandleCommand('expression -lobjc  -O -- ' + command_script, res)
        if res.GetError():
            result.SetError(res.GetError()) 
            return
        contents = res.GetOutput()

        create_or_touch_filepath(filepath, contents)
        print('Written output to: ' + filepath + '... opening file')
        os.system('open -R ' + filepath)

    elif options.filter and clean_command:
        print('Dumping classes for: ' + clean_command + ', with filter: ' + options.filter)
        debugger.HandleCommand('expression -lobjc -O -- ' + command_script)
    elif clean_command:
        print('Dumping classes for: ' + clean_command)
        debugger.HandleCommand('expression -lobjc -O -- ' + command_script)
    else:
        print('Dumping all classes...')
        debugger.HandleCommand('expression -lobjc -O -- ' + command_script)


def generate_class_dump(options, clean_command=None):
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
        
        [generatedPropertyString appendString:(NSString *)[[NSString alloc] initWithFormat:@"getter=%@", [parsedInput substringFromIndex:1]]];
        multipleOptions = 1;
      } else if ([parsedInput hasPrefix:@"S"]) {
        if (multipleOptions) {
          [generatedPropertyString appendString:@", "];
        }
        
        [generatedPropertyString appendString:(NSString *)[[NSString alloc] initWithFormat:@"setter=%@", [parsedInput substringFromIndex:1]]];
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
            } else {
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
    NSString *setter = (NSString *)[@"set" stringByAppendingString:[propertyName capitalizedString]];
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
        
        [realizedMethod appendFormat:(NSString *)[[NSString alloc] initWithFormat:@"arg%d ", index]];
        
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
  Class metaClass = objc_getMetaClass(cls);
  NSString *generatedClassMethods = generateMethodsForClass(metaClass);
  

  NSMutableString *finalString = [NSMutableString string];
  [finalString appendString:@"#import <Foundation/Foundation.h>\n\n"];'''

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
    return parser

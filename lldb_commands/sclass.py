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
        'command script add -f sclass.sclass sclass')


def sclass(debugger, command, result, internal_dict):
    '''
    Swizzle Class. Generates a NSObject category file 
    that swizzles the class that you supply. 

Examples:

    # Generates a category to swizzle all created or overriden methods in UIViewController
    sclass UIViewController

    # Only generate a category to swizzle viewDidLoad
    sclass UIViewController -m viewDidLoad

    # Generates a category which prints all functions when executed
    sclass UIViewController -p

    # Generates a category which stops every time the method is hit
    sclass UIViewController -s

    # Generates a category which enables all swizzles to be enabled by default
    sclass UIViewController -e
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    if not args:
        result.SetError('usage: sclass NSObjectSubclass')
        return
    clean_command = ('').join(args)

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    interpreter.HandleCommand('expression -lobjc -O -- @import Foundation', res)
    interpreter.HandleCommand('expression -lobjc -O -- @import ObjectiveC', res)
    res.Clear()

    target = debugger.GetSelectedTarget()
    interpreter.HandleCommand('expression -lobjc -O -- (Class)NSClassFromString(@\"{}\")'.format(clean_command), res)
    if 'nil' in res.GetOutput():
        result.SetError('Can\'t find class named "{}". Womp womp...'.format(clean_command))
        return
    res.Clear()

    command_script = generate_header_script(options, clean_command)
    filepath = "/tmp/NSObject+DS_" + clean_command + ".m"
    interpreter.HandleCommand('expression -lobjc -O -- ' + command_script, res)
        # debugger.HandleCommand('expression -lobjc -O -g -- ' + command_script)
    if res.GetError():
        result.SetError(res.GetError()) 
        return
    contents = generate_swizzle_block(clean_command) + res.GetOutput()

    if options.copy_compile:
        if 'x86_64h-apple-ios' in target.GetTriple():
            archType = '-sdk iphonesimulator'
        elif 'arm64' in target.GetTriple():
            archType = '-sdk iphoneos'
        else:
            archType = ''


        compileString = 'clang {} -dynamiclib -Wl, -isysroot `xcrun --show-sdk-path {}` -framework Foundation -framework UIKit -framework QuartzCore -o /tmp/a.dylib && codesign --force --sign - /tmp/a.dylib'.format(filepath, archType)
        os.system('echo "{}" | pbcopy'.format(compileString))
        result.AppendMessage('Copying build command to clipboard')
        contents = '/*\n{}\n*/\n\n'.format(compileString) + contents

    create_or_touch_filepath(filepath, contents)
    result.AppendMessage('Written output to: ' + filepath + '... opening file')
    os.system('open -R ' + filepath)


def generate_swizzle_block(class_to_generate_header):
    return  r'''#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CoreGraphics/CoreGraphics.h>

@interface NSObject (DS_''' + class_to_generate_header + r'''_Swizzle)
@end

@implementation NSObject (DS_''' + class_to_generate_header + r'''_Swizzle)

+ (void)load { 

    __unused void (^swizzle)(NSString *, BOOL) = ^(NSString *method, BOOL isClassMethod ) {
    NSString *randString = @"''' + class_to_generate_header + r'''";
    NSString *swizzledString = [(NSString *)[(NSString *)[@"ds" stringByAppendingString:randString] stringByAppendingString:@"_"] stringByAppendingString:method];;
    
    Class cls = NSClassFromString(@"''' + class_to_generate_header + r'''");

    SEL originalSelector = NSSelectorFromString(method);
    SEL swizzledSelector = NSSelectorFromString(swizzledString);
    
    Method originalMethod;
    Method swizzledMethod;
    
    if (isClassMethod) {
      originalMethod = class_getClassMethod(cls, originalSelector);
      swizzledMethod = class_getClassMethod(cls, swizzledSelector);
    } else {
      originalMethod = class_getInstanceMethod(cls, originalSelector);
      swizzledMethod = class_getInstanceMethod(cls, swizzledSelector);
    }
    
    BOOL didAddMethod =
    class_addMethod(cls,
                    originalSelector,
                    method_getImplementation(swizzledMethod),
                    method_getTypeEncoding(swizzledMethod));
    
    if (didAddMethod) {
      class_replaceMethod(cls,
                          swizzledSelector,
                          method_getImplementation(originalMethod),
                          method_getTypeEncoding(originalMethod));
    } else {
      method_exchangeImplementations(originalMethod, swizzledMethod);
    }
  };
  '''

def generate_header_script(options, class_to_generate_header):
    script = '''

  @import @ObjectiveC;
  @import @Foundation;

  typedef struct objc_method *Method;
  typedef struct objc_ivar *Ivar;
  // typedef struct objc_category *Category;
  typedef struct objc_property *objc_property_t;
  
  NSString *randString = @"''' + class_to_generate_header + r'''";
  NSMutableString *returnString = [NSMutableString string];
  // Properties
  NSMutableSet *blackListMethodNames = [NSMutableSet set];
  NSMutableSet *exportedClassesSet = [NSMutableSet set];
  
  [blackListMethodNames addObjectsFromArray:@[@".cxx_destruct", @"dealloc", @"retain", @"release", @"autorelease", @"_tryRetain", @"class", @"_isDeallocating", @"hash"]];
  Class cls = NSClassFromString(@"''' + class_to_generate_header + r'''");
  
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
  
  NSMutableString *swizzledImplementationsString = [NSMutableString string];
  [swizzledImplementationsString appendString:@"\n  static dispatch_once_t onceToken;\n  dispatch_once (&onceToken, ^{"];

  NSString *(^generateMethodsForClass)(Class) = ^(Class cls) {
    NSMutableString* generatedMethods = [NSMutableString stringWithString:@""];
    unsigned int classCount = 0;
    Method *methods = (Method *)class_copyMethodList(cls, &classCount);
    NSString *classOrInstanceStart = (BOOL)class_isMetaClass(cls) ? @"+" : @"-";
    
    
    for (int i = 0; i < classCount; i++) {

      Method m = methods[i];
      NSString *methodName = NSStringFromSelector((SEL)method_getName(m));
      '''
    if options.method:
        script += r'if (!(BOOL)[methodName isEqualToString:@"' + options.method + '"]) { continue; }'

    if options.regex_method:
        script += 'NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"{}" options:0 error:nil];'.format(options.regex_method)
        script += r'''
    NSUInteger matches = (NSUInteger)[regex numberOfMatchesInString:methodName options:0 range:NSMakeRange(0, [methodName length])];
    if (matches == 0) {
      continue;
    }'''

    script += r''' 
      if([blackListMethodNames containsObject:methodName]) {
        continue;
      }'''
    if options.enable_all:
        script += r'[swizzledImplementationsString appendString:@"\n  swizzle(@\""];'
    else:
        script += r'[swizzledImplementationsString appendString:@"\n  // swizzle(@\""];'

    script += r'''
      [swizzledImplementationsString appendString:methodName];
      [swizzledImplementationsString appendString:@"\", "];
      
      if (class_isMetaClass(cls)) {
        [swizzledImplementationsString appendString:@"YES"];
      } else {
        [swizzledImplementationsString appendString:@"NO"];
      }
      
      [swizzledImplementationsString appendString:@");"];
      
      
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
      
      BOOL shouldAddReturn = NO;
      if ((BOOL)![argumentBlock(retTypeString) isEqualToString:@"void"]) {
        shouldAddReturn = YES;
      }
      NSMutableString *realizedMethod = [NSMutableString stringWithString:@""];
      [realizedMethod appendString:@"ds"];
      [realizedMethod appendString:randString];
      [realizedMethod appendString:@"_"];
      
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
      
      
      [generatedMethods appendString:(NSString *)[generatedMethodString stringByAppendingString:@" {\n"]];
      '''
    if options.stop_execution:
        script += r'[generatedMethods appendString:@"  raise(17);\n"];'

    if options.print_function:
        script += r'[generatedMethods appendString:@"  printf(\"%s\\n\", __FUNCTION__);\n"];'

    script += r'''
      [generatedMethods appendString:@"  "];
      if (shouldAddReturn) {
        [generatedMethods appendString:@"return "];
      }
      
      [generatedMethods appendString:@"[self ds"];
      [generatedMethods appendString:randString];
      [generatedMethods appendString:@"_"];
      if ([methodName containsString:@":"]) {
        
        NSArray *components = (NSArray *)[methodName componentsSeparatedByString:@":"];
        for (int i = 0; i < [components count]; i++) {
          NSString *component = (NSString *)[components objectAtIndex:i];
          if ((int)[component length] == 0) {
            continue;
          }
          [generatedMethods appendString:component];
          [generatedMethods appendString:@": arg"];
          [generatedMethods appendString:[@(i) stringValue]];
          [generatedMethods appendString:@" "];
        }
      } else {
        [generatedMethods appendString:methodName];
      }
      
      [generatedMethods appendString:@"];\n}\n\n\n"];
    }
      
    free(methods);
    return (NSString *)generatedMethods;
  };
  // Instance Methods
  NSString *generatedInstanceMethods = generateMethodsForClass((Class)cls);
  
  // Class Methods
  Class metaClass = (Class)objc_getMetaClass((char *)class_getName(cls));
  NSString *generatedClassMethods = generateMethodsForClass(metaClass);
  
  
  NSMutableString *finalString = [NSMutableString string];
  NSMutableString *loadCommandString = [NSMutableString string];
  
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
  
  [swizzledImplementationsString appendString:@"\n  });\n"];

  [loadCommandString appendString:swizzledImplementationsString];
  [loadCommandString appendString:@"\n}\n"];
  

  [returnString appendString:@""];
  [finalString appendString:loadCommandString];
  [finalString appendString:generatedClassMethods];
  [finalString appendString:generatedInstanceMethods];
  [finalString appendString:@"\n@end"];
  [returnString appendString:finalString];
  
  returnString
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
    parser.add_option("-p", "--print_function",
                      action="store_true",
                      default=False,
                      dest="print_function",
                      help="Will print the file for all swizzled methods")

    parser.add_option("-e", "--enable_all",
                      action="store_true",
                      default=False,
                      dest="enable_all",
                      help="Enable all swizzled methods (do not comment them out)")

    parser.add_option("-s", "--stop_execution",
                      action="store_true",
                      default=False,
                      dest="stop_execution",
                      help="If true, this will create a breakpoint on all the swizzled functions")

    parser.add_option("-m", "--method",
                      action="store",
                      default=None,
                      dest="method",
                      help="Instead of dumping all the functions only specify a module, expects Selector style input")

    parser.add_option("-c", "--copy_compile",
                      action="store_true",
                      default=False,
                      dest="copy_compile",
                      help="Copy the compile command to compile the category to the clipboard")

    parser.add_option("-r", "--regex_method",
                      action="store",
                      default=None,
                      dest="regex_method",
                      help="Only generate methods to swizzle based upon a regex expression")
    return parser

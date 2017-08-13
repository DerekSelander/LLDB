# LLDB

<a href="https://amzn.to/2rApgj9" target="_blank"><img align="right" src="Media/dbgbook.png"></a>
A collection of LLDB aliases/regexes and Python scripts to aid in my debugging sessions. These scripts are built only for my  own amusement, but some of them might be helpful in your own work. If you want to gain a better understanding of how to build these LLDB scripts, or gain a better understanding of LLDB in general, check out <a href="https://amzn.to/2rApgj9" target="_blank">**Advanced Apple Debugging and Reverse Engineering**</a>


## Installation 

1. To Install, copy the **lldb_commands** folder to a dir of your choosing.
2. Open up **~/.lldbinit** or `touch ~/.lldbinit` if that file doesn't exist
3. Add the following command to your ~/.lldbinit file: `command script import /path/to/lldb_commands/dslldb.py`

Boom! You're good to go!

You can test to make sure everything worked successfully by just trying one of the commands in the debugger... i.e. `(lldb) help methods`


## LLDB Commands

### ls 
List a directory from the process's perspective. Useful when working on an actual device. 
```
command regex ls 's/(.+)/expression -lobjc -O -- @import Foundation; NSError *err = nil; NSArray *arr = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"%1" error:&err]; id retValue = err ? [err localizedDescription] : arr; retValue/'
```
  Example: 
      
      (lldb) ls /
      (lldb) ls /System/Library
      
### reload_lldbinit
Reloads all the contents in your ~/.lldbinit file. Useful for seeing if your python script(s) broke or want to do incremental updates to a python script

```
command alias reload_lldbinit command source ~/.lldbinit
```

### tv
Toggle view. Hides/Shows a view depending on it's current state. You don't need to resume LLDB to see changes. ObjC only

```
command regex -- tv 's/(.+)/expression -l objc -O -- @import QuartzCore; [%1 setHidden:!(BOOL)[%1 isHidden]]; (void)[CATransaction flush];/'
```

### pprotocol
Dumps all the required and optional methods for specific protocol (Objective-C only)

    (lldb) pprotocol UITableViewDataSource

```
command regex protocol 's/(.+)/expression -lobjc -O -- @import Foundation; NSMutableString *string = [NSMutableString string]; Protocol * prot = objc_getProtocol("%1"); [string appendFormat:@"\nProtocol: %s, %@\n", (char *)[prot name], (id)prot]; [string appendString:@"==========================================\n"]; for (int isRequired = 1; isRequired > -1; isRequired--) { [string appendFormat:@" (%@)\n", isRequired ? @"Required" : @"Optional"]; for (int isInstanceMethod = 0; isInstanceMethod < 2; isInstanceMethod++) { unsigned int ds_count = 0; struct objc_method_description * methods = (struct objc_method_description *)protocol_copyMethodDescriptionList(prot, (BOOL)isRequired, (BOOL)isInstanceMethod, &ds_count); for (int i = 0; i < ds_count; i++) { struct objc_method_description method = methods[i]; [string appendFormat:@"%@ %@, %s\n", isInstanceMethod ? @"-": @"+", NSStringFromSelector(method.name), method.types]; }}} string;/'
```

### methods 
Dumps all methods inplemented by the NSObject subclass (iOS, NSObject subclass only)

    (lldb) methods UIView 
```
command regex methods 's/(.+)/expression -lobjc -O -- [%1 _shortMethodDescription]/'
```

### ivars
Dumps all ivars for an instance of a particular class which inherits from NSObject (iOS, NSObject subclass only)

    (lldb) ivars [UIView new]
    
```
command regex ivars 's/(.+)/expression -lobjc -O -- [%1 _ivarDescription]/'
```

# LLDB Scripts

For all commands below, you can view the documentation via `help {command}`. If you want to see what options a command has, type `{command} -h`.

TLDR: `search`, `lookup`, and `dclass` are good GOTOs irregardless if you're a dev or exploring without source. 

If you like ObjC swizzling, check out `sclass`. If you like DTrace, check out `pmodule` and `snoopie`.

### search
  Searchs the heap for all alive instances of a certain class. This class must by dynamic (aka inherit from a NSObject class). Currently doesn't work with NSString or NSNumber (tagged pointer objects). 
  
  Example: 
  
      # Find all instances and subclasses of UIView
      (lldb)  search UIView
      
      # Find all instances of UIView that are UIViews. Ignore subclasses.
      (lldb) search UIView -e
      
      #Find all instances of UIView whose tag is equal to 5. Objective-C syntax only. Can reference object by 'obj'
      (lldb) search UIView -c "(int)[obj tag]==5"
      
      # Find all instances of a UIView subclass whose class is implemented in the SpringBoardUI module
      (lldb) search UIView -m SpringBoardUI

### dclass
Dumps all the NSObject inherited classes in the process. If you give it a module, it will dump only the classes within that module. You can also filter out classes to only a certain type and can also generate a header file for a specific class.
  
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

      # Only dump classes whose superclass is of type NSObjecr and in the UIKit module. Ideal for going after specific classes like a datasource where it will likely inherit from NSObject
      (lldb) dclass -s NSObject -m UIKit

### dd
Alternative to LLDB's `disassemble` command. Uses colors. Terminal only
![yoink example](https://github.com/DerekSelander/LLDB/raw/master/Media/dd.png)

### sbt
      Symbolicate backtrace. Will symbolicate a stripped backtrace from an executable if the backtrace is using Objective-C 
      code. Currently doesn't work on aarch64 stripped executables but works great on x64 :]
      
      You learn how to make this command in the book :]
      

![sbt example](https://github.com/DerekSelander/LLDB/raw/master/Media/sbt_gif.gif)

### msl

      msl 0xadd7e55
      msl or malloc stack logging will take an address and try and obtain the stack trace to 
      when it was created. 

      You will need to set the env var to MallocStackLogging, or `execute turn_on_stack_logging(1)`
      while the process is active
      
      You learn how to make this command in the book :]
      
![msl example](https://github.com/DerekSelander/LLDB/raw/master/Media/msl_gif.gif) 

### lookup
Perform a regular expression search for stuff in an executable

  Example:
  
      # Find all methods that contain the phrase viewDidLoad
      (lldb) lookup viewDidLoad
      
      # Find a summary of all the modules that have a (known) function containing the phrase viewDidLoad
      (lldb) lookup viewDidLoad -s
      
      # Search for Objective-C code in a stripped module (i.e. in SpringBoard)
      (lldb) loo -x StocksFramework .
      
      # Search for Objective-C code containing the case insensitive phrase init inside a stripped main bundle
      (lldb) lookup -X (?i)init
      
      # Search for all hardcoded, embeded `char *` inside an executable containing the phrase *http* inside UIKit
      (lldb) lookup -S http -m UIKit
      
      # Dump all the md5'd base64 keys in libMobileGestalt along w/ the address in memory
      (lldb) loo -S ^[a-zA-Z0-9\+]{22,22}$ -m libMobileGestalt.dylib -l
      
      # Dump all the global bss code referenced by DWARF. Ideal for accessing `static` variables when not in scope
      (lldb) lookup . -g HonoluluArt -l
      
### biof
    Break if on func. Syntax: biof [ModuleName] regex1 ||| [ModuleName2] regex2
    Regex breakpoint that takes two regex inputs. The first regex creates a breakpoint on all matched functions.
    The second regex will make a breakpoint condition to stop only if the second regex breakpoint is in the stack trace
    
    For example, to only stop if code in the "TestApp" module resulted in executing the setTintColor: method being called
    biof setTintColor: ||| . Test 
    
    As a tip, it would be wise to have a limited regex1 that matches a small amount of functions, while keeping regex2 at any size

### yoink

  Takes a path on a iOS/tvOS/watchOS and writes to the **/tmp/** dir on your computer.
  If it can be read by `-[NSData dataWithContentsOfFile:]`, it can be written to disk

  Example (on iOS 10 device): 
  
      (lldb) yoink /System/Library/Messages/iMessageEffects/CKConfettiEffect.bundle/CKConfettiEffect

![yoink example](https://github.com/DerekSelander/LLDB/raw/master/Media/yoink_gif.gif)

### pmodule

  Creates a custom dtrace script that profiles modules in an executable based upon its 
  memory layout and ASLR. Provide no arguments w/ '-a' if you want a count of all the modules firing. 
  Provide a module if you want to dump all the methods as they occur. The location of the script is 
  copied to your computer so you can paste the soon to be executed dtrace script in the Terminal. 
  
  WARNING: YOU MUST DISABLE ROOTLESS TO USE DTRACE
  
      # Trace all Objective-C code in UIKit 
      (lldb) pmodule UIKit

      # Trace all non-Objective-C code in libsystem_kernel.dylib (i.e. pid$target:libsystem_kernel.dylib::entry)
      (lldb) pmodule -n libsystem_kernel.dylib
      
      # Dump errrything. Only displays count of function calls from modules after you end the script. Warning slow
      (lldb) pmodule -a
      
![pmodule example](https://github.com/DerekSelander/LLDB/raw/master/Media/pmodule_gif.gif)

### snoopie
    Generates a DTrace sciprt that will only profile classes implemented
    in the main executable irregardless if binary is stripped or not. This is done via 
    profiling objc_msgSend. The creation of this command is discussed in the book.

  WARNING: YOU MUST DISABLE ROOTLESS TO USE DTRACE

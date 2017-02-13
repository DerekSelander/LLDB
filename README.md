# LLDB
A collection of LLDB aliases/regexes and Python scripts to aid in your debugging sessions

## Installation 

For scripts (anything ending with `.py`), you'll need to do the following: 
  1. Download scripts. Install to a dir of your choosing (i.e. `~/lldb`)
  2. In `~/.lldbinit` add the following:
      `command script import path/to/lldb_file.py`
  
  You must import each file individually in your lldbinit file

For any lldb commands simply just paste the command into your `~/.lldbinit` file


## LLDB Commands

### ls 
List a directory from the process's perspective. Useful when working on an actual device. 
```
command regex ls 's/(.+)/po @import Foundation; [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"%1" error:nil]/'
```
  Example: 
      
      (lldb) ls /
      (lldb) ls /System/Library
      
### reload_lldbinit
Reloads all the contents in your ~/.lldbinit file. Useful for seeing if your python script(s) broke or want to do incremental updates to a python script

```
command alias reload_lldbinit command source ~/.lldbinit
```

## LLDB Scripts
### dump_classes
Dumps all the NSObject inherited classes in the process. If you give it a module that exists on disk, it will dump only the classes within that module. You can also filter out classes to only a certain type of class.
  
  Example: 
  
      # Dump ALL the NSObject classes within the process
      (lldb) dump_classes 

      # Dump all the classes that are a UIViewController within the process
      (lldb) dump_classes -f UIViewController

      # Dump all classes in CKConfettiEffect NSBundle that are UIView subclasses
      (lldb) dump_classes /System/Library/Messages/iMessageEffects/CKConfettiEffect.bundle/CKConfettiEffect -f UIView

### find
  Finds all subclasses of a class. This class must by dynamic (aka inherit from a NSObject class). Currently doesn't work with   NSString or NSNumber (tagged pointer objects). 
  
  Example: 
  
      # Find all instances and subclasses of UIView
      (lldb)  find UIView
      
      # Find all instances of UIView that are UIViews. Ignore subclasses.
      (lldb) find UIView -e
      
      #Find all instances of UIView whose tag is equal to 5. Objective-C syntax only. Can reference object by 'obj'
      (lldb) find UIView -c "[obj tag]==5"

### yoink

  Takes a path on a iOS/tvOS/watchOS and writes to the **/tmp/** dir on your computer.
  If it can be read by `-[NSData dataWithContentsOfFile:]`, it can be written to disk

  Example (on iOS 10 device): 
  
      (lldb) yoink /System/Library/Messages/iMessageEffects/CKConfettiEffect.bundle/CKConfettiEffect

![yoink example](https://github.com/DerekSelander/LLDB/raw/master/Media/yoink_gif.gif)

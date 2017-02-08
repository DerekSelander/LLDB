# LLDB
A collection of LLDB aliases/regexes and Python scripts to aid in your debugging sessions


### yoink

  Takes a path on a iOS/tvOS/watchOS and writes to the /tmp/ dir on your computer.
  If it can be read by -[NSData dataWithContentsOfFile:], it can be written to disk

  Example (on iOS 10 device): 
  
      (lldb) yoink /System/Library/Messages/iMessageEffects/CKConfettiEffect.bundle/CKConfettiEffect

![yoink example](https://github.com/DerekSelander/LLDB/raw/master/Media/yoink_gif.gif)

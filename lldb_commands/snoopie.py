

import lldb
import os
import shlex
import optparse
from stat import *

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f snoopie.handle_command snoopie')

def handle_command(debugger, command, result, internal_dict):
    '''
    Generates a DTrace sciprt that will only profile classes implemented
    in the main executable irregardless if binary is stripped or not.
    '''

    script = generateDTraceScript(debugger)
    pid = debugger.GetSelectedTarget().process.id
    filename = '/tmp/lldb_dtrace_profile_snoopie.d'
    
    createOrTouchFilePath(filename, script)
    cmd = 'sudo {0}  -p {1}'.format(filename, pid)
    copycommand = 'echo \"{} \" | pbcopy'.format(cmd)
    os.system(copycommand)

    result.AppendMessage('Copied script to clipboard... paste in Terminal')

def createOrTouchFilePath(filepath, dtrace_script):
    file = open(filepath, "w")
    file.write(dtrace_script)
    file.flush()
    st = os.stat(filepath)
    os.chmod(filepath, st.st_mode | S_IEXEC)
    file.close()


def generateDTraceScript(debugger):
    target = debugger.GetSelectedTarget()
    path = target.executable.fullpath
    section = target.module[path].section['__DATA']
    start_address = section.GetLoadAddress(target)
    end_address = start_address + section.size

    dataSectionFilter = '''{} <= *((uintptr_t *)copyin(arg0, sizeof(uintptr_t))) && 
                                *((uintptr_t *)copyin(arg0, sizeof(uintptr_t))) <= {}'''
                                
    dataSectionFilter = dataSectionFilter.format(start_address, end_address)

    predicate = '''/ arg0 > 0x100000000 &&
                      {} &&
                      this->selector != "retain" &&  
                      this->selector != "release" /'''.format(dataSectionFilter)


    script = r'''#!/usr/sbin/dtrace -s
#pragma D option quiet  

dtrace:::BEGIN
{
    printf("Starting... Hit Ctrl-C to end.\n");
}

pid$target::objc_msgSend:entry 
{
  this->selector = copyinstr(arg1); 
}

pid$target::objc_msgSend:entry ''' + predicate + r'''  
{
  size = sizeof(uintptr_t);  
  this->isa = *((uintptr_t *)copyin(arg0, size));
  this->rax = *((uintptr_t *)copyin((this->isa + 0x20), size)); 
  this->rax =  (this->rax & 0x7ffffffffff8); 
  this->rbx = *((uintptr_t *)copyin((this->rax + 0x38), size)); 

  this->rax = *((uintptr_t *)copyin((this->rax + 0x8),  size));  
  this->rax = *((uintptr_t *)copyin((this->rax + 0x18), size));  

  this->isMetaFlag = *((uintptr_t *)copyin((this->isa + 0x20), size));  
  this->isMetaFlag = *((uintptr_t *)copyin((this->isa + 0x8), size)) & 1;  
  this->isMeta = this->isMetaFlag ? '+' : '-';


  this->classname = copyinstr(this->rbx != 0 ? 
                               this->rbx  : this->rax);   

  this->misa = *((uintptr_t *)copyin(this->isa, size));
  this->mrax = *((uintptr_t *)copyin((this->misa + 0x20), size)); 
  this->mrax =  (this->mrax & 0x7ffffffffff8); 
  this->mrbx = *((uintptr_t *)copyin((this->mrax + 0x38), size)); 

  this->mrax = *((uintptr_t *)copyin((this->mrax + 0x8),  size));  
  this->mrax = *((uintptr_t *)copyin((this->mrax + 0x18), size));  

  this->mclassname = copyinstr(this->mrbx != 0 ? 
                               this->mrbx  : this->mrax);   

  this->instanceOrClass = (this->mclassname == this->classname) ? '-' : '+';

  printf("0x%016p %c[%s %s]\n", arg0, this->instanceOrClass, this->classname, 
                                       this->selector);
}'''
    return script


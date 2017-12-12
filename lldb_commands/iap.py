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


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f iap.iap iap')


def iap(debugger, command, exe_ctx, result, internal_dict):
    '''
    iap expects at least one argument. The following arguments are currently supported

        iap get 
            gets the iAP receipt, if exists


        iap stat 
            gets the status of the iAP receipt on device if any


    '''
#  Not functional yet... or ever
# iap put /path/to/receipt/on/computer
#     puts a iAP receipt on device, overwrites existing receipt, expects a parameter to path
# iap del
#     deletes the current receipt stored on the device

    command_args = shlex.split(command)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    clean_command = ('').join(args)
    if len(args) < 1:
        result.SetError(parser.usage)
        return


    if args[0] ==  "get":
        getiAPReceipt(result, debugger)
    elif args[0] == "stat":
        statiAPReceipt(result, debugger)
    # elif args[0] == "del":
    #     deliApReceipt(result, debugger)
    # elif args[0] == "put":
    #     print("still being worked on, womp")
        # putiAPReceipt(result, debugger)



def putiAPReceipt(result, debugger):
    command_script = r'''
    @import Foundation; 
    id path = [[[NSBundle mainBundle] appStoreReceiptURL] path]; 

    NSError *error;
    BOOL success = [fileManager removeItemAtPath:path error:&error];
    error ? [NSString stringWithFormat:@"Successfully deleted receipt!\n%@\n\nMD5 Hash: %@", path, output] : [NSString stringWithFormat:@"Error: %@", error]
    '''

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)
    if not res.HasResult():
        result.SetError('There\'s no result ' + res.GetError())
        return

    result.AppendMessage(res.GetOutput())
    

def deliApReceipt(result, debugger):
    command_script = r'''
    @import Foundation; 
    id path = [[[NSBundle mainBundle] appStoreReceiptURL] path]; 

    NSError *error;
    BOOL success = (BOOL)[[NSFileManager defaultManager] removeItemAtPath:path error:&error];
    success ? [NSString stringWithFormat:@"Successfully deleted receipt!\n%@", path] : [NSString stringWithFormat:@"Error: %@", error]
    '''

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)
    if not res.HasResult():
        result.SetError('There\'s no result ' + res.GetError())
        return

    result.AppendMessage(res.GetOutput())


def statiAPReceipt(result, debugger):
    command_script = r'''
    @import Foundation; 
    id path = [[[NSBundle mainBundle] appStoreReceiptURL] path]; 
    id data = [NSData dataWithContentsOfFile:path];

    unsigned char md5Buffer[12];
 
    CC_MD5((void*)[data bytes], (unsigned long)[data length], md5Buffer);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:12 * 2];
    for(int i = 0; i < 12; i++)  {
        [output appendFormat:@"%02x",md5Buffer[i]];
    }
  
    data ? [NSString stringWithFormat:@"Receipt found!\n%@\n\nMD5 Hash: %@", path, output] : @"No receipt :["
    '''

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)
    if not res.HasResult():
        result.SetError('There\'s no result ' + res.GetError())
        return

    result.AppendMessage(res.GetOutput())


def getiAPReceipt(result, debugger):
    command_script = r'''
    @import Foundation; 
    id path = [[[NSBundle mainBundle] appStoreReceiptURL] path];
    id data = [NSData dataWithContentsOfFile:path];
data ? [NSString stringWithFormat:@"%p,%p,%p,%@", data, (uintptr_t)[data bytes], (uintptr_t)[data length] + (uintptr_t)[data bytes], path] : @"No receipt :["'''
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()

    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)
    if not res.HasResult():
        result.SetError('There\'s no result ' + res.GetError())
        return

    response = res.GetOutput().split(',')

    if len(response) is not 4:
        result.SetError('Bad Fromatting')
        return

    if int(response[0], 16) is 0:
        result.SetError('Couldn\'t open file {}'.format(clean_command))
        return

    basename = os.path.basename(response[3]).strip()
    debugger.HandleCommand(
        'memory read {} {} -r -b -o /tmp/{}'.format(response[1], response[2], basename))

    interpreter.HandleCommand('po [{} dealloc]'.format(response[0]), res)

    fullpath = '/tmp/{}'.format(basename)

    print('Opening file...')
    os.system('open -R \"{}\"'.format(fullpath))





import lldb
import os
import shlex
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f keychain.handle_command keychain -h "iOS keychain methods"')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    keychain will dump all the generic password and generic internet passwords
    known to the process (iOS only).

    If you give an argument, keychain will only return the hits that match either
    the service or the account name

    You iOS device must be turned on, keychain will not return any hits if the device is locked

    For example: 

    # Dump all password content for a process 
    keychain

    # Dump content whose service or account name contains "tmp"
    keychain tmp

    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    # Uncomment if you are expecting at least one argument
    # clean_command = shlex.split(args[0])[0]


    if len(args) > 0:
        script = generate_script_info(args[0])
    else:
        script = generate_script_info(None)


    debugger.HandleCommand('exp -lobjc -O -- ' + script)
    # result.AppendMessage('Hello! the keychain command is working!')


def generate_script_info(query):
    if query:
        script = "NSString *queryString = @\"" + query + "\";"
    else:
        script = "NSString *queryString = nil;"

    script += r'''
   NSMutableDictionary *query = [NSMutableDictionary dictionaryWithDictionary:
                                  @{ (id)@"r_Attributes" : (id)@YES,
                                    (id)@"r_Data" : (id)@YES,
                                     (id)@"m_Limit" : (id)@"m_LimitAll"}];
    
    
    NSArray *secItemClasses =  @[(id)@"genp", /* kSecClassGenericPassword  */
                                 (id)@"inet", /* kSecClassInternetPassword */
                                 (id)@"cert", /* kSecClassCertificate */
                                 (id)@"keys", /* kSecClassKey */
                                 (id)@"idnt", /* kSecClassIdentity */ ];
    
    NSMutableArray *returnArray = [NSMutableArray new];
    for (id secItemClass in secItemClasses) {
        [query setObject:secItemClass forKey:(id)@"class"];
        
        CFTypeRef result = NULL;
        SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        
        NSArray *keychainArray = (__bridge id _Nullable)(result);
        NSDictionary * (^grabContents)(NSDictionary *) = ^NSDictionary* (NSDictionary *dict) {
            NSMutableDictionary *returnDict = [NSMutableDictionary new];
            if ([dict objectForKey:@"agrp"]) {
                [returnDict setObject:(id)[dict objectForKey:(id)@"agrp"] forKey:(id)@"agrp"];
            }
            if ([dict objectForKey:@"acct"]) {
                [returnDict setObject:(id)[dict objectForKey:(id)@"acct"] forKey:(id)@"acct"];
            }
            if ([dict objectForKey:@"v_Data"]) {
                
                NSData *data = [dict objectForKey:@"v_Data"];
                 id receivedObject; 
                 if ((int)[data length]) {
                   receivedObject = [NSKeyedUnarchiver unarchiveObjectWithData:data];
                 }
                NSString *str = [[NSString alloc] initWithData:data encoding:4];
                if (str) {
                    [returnDict setObject:str forKey:(id)@"v_Data (str)"];
                } 
              else if ((BOOL)[receivedObject isKindOfClass:(id)[NSArray class]]) {
                    [returnDict setObject:receivedObject forKey:(id)@"v_Data (arr)"];
                } else if ((BOOL)[receivedObject isKindOfClass:(id)[NSDictionary class]]) {
                    [returnDict setObject:receivedObject forKey:(id)@"v_Data (dict)"];
                } else if ((BOOL)[receivedObject isKindOfClass:[NSObject class]]) {
                    NSMutableString *dskey = [NSMutableString string];
                    [dskey appendString:(id)@"v_Data ("];
                    [dskey appendString:(id)NSStringFromClass((id)[receivedObject class])];
                    [dskey appendString:(id)@")"];
                    [returnDict setObject:receivedObject forKey:(id)dskey];
                } else {
                    [returnDict setObject:data forKey:(id)@"v_Data (error)"];
                }
            } else {
                [returnDict setObject:@"[NONE]" forKey:(id)@"v_Data"];
            }
            return returnDict;
        };
        if ((BOOL)[keychainArray isKindOfClass:[NSArray class]]) {
            for (id dsitem in keychainArray) {
                if ((BOOL)[dsitem isKindOfClass:[NSDictionary class]]) {
                    if (queryString) {
                        if (([(NSString *)[dsitem objectForKey:@"agrp"] containsString:queryString] || [(NSString *)[dsitem objectForKey:@"acct"] containsString:queryString])) {
                            [returnArray addObject:(id)grabContents(dsitem)];
                        }
                    } else {
                            [returnArray addObject:(id)grabContents(dsitem)];
                            }
                } else {
                    [returnArray addObject:(id)grabContents(dsitem)];
                }
            }
            if (result != NULL) {
                CFRelease(result);
            }
        }
        
    }
    [returnArray debugDescription]
    '''
    return script

def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="keychain")
    # parser.add_option("-m", "--module",
    #                   action="store",
    #                   default=None,
    #                   dest="module",
    #                   help="This is a placeholder option to show you how to use options with strings")
    # parser.add_option("-c", "--check_if_true",
    #                   action="store_true",
    #                   default=False,
    #                   dest="store_true",
    #                   help="This is a placeholder option to show you how to use options with bools")
    return parser
    
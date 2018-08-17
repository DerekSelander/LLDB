

import lldb
import os
import shlex
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f dumpenv.handle_command dumpenv -h "Short documentation here"')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Documentation for how to use dumpenv goes here 
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

    script = r'''
  extern void *&environ;
  NSMutableString *retString = [NSMutableString new];
  for (char **env = (char**)environ; *env != 0; env++)
  {
    char *cur = *env;
    [retString appendString:[NSString stringWithUTF8String:cur]];
    [retString appendString:@"\n\n"];
  }
  retString;
    '''
    debugger.HandleCommand("exp -l objc -O -- " + script)
    # result.AppendMessage('Hello! the dumpenv command is working!')


def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="dumpenv")
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
    
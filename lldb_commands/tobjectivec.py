

import lldb
import os
import shlex
import optparse
import os
import subprocess
import textwrap
from stat import *

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f tobjectivec.handle_command tobjectivec')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Creates a dtrace script and copies to your clipboard
    sudo dtrace provider:module:function:name / predicate / { action }
    '''

    command_args = shlex.split(command.replace('-', '\-'))
    parser = generateOptionParser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    script = generateDTraceScript(debugger, options)


    pid = debugger.GetSelectedTarget().process.id
    filename = '/tmp/lldb_dtrace_profile_objc.d'

    
    createOrTouchFilePath(filename, script)
    cmd = 'sudo {0}  -p {1}'.format(filename, pid)

    if options.debug or options.listprobes:
        result.AppendMessage("\n{}\n".format(script))
        if options.debug:
            return

    source = '\n'.join(['# '+ format(idx + 1, '2') +': ' + line for idx, line in enumerate(script.split('\n'))]) + '\n' if options.debug_with_clipboard else ''
    stderr = "2>/dev/null" if not options.debug_with_clipboard else ''
    copycommand = 'echo \"{} {}  {}\" | pbcopy'.format(source.replace('$', '\$'), cmd, stderr)
    os.system(copycommand)
    if options.debug_with_clipboard:
        result.AppendMessage("Copied dryrun script to clipboard... paste in Terminal. Will ensure it compiles then exit")
    elif options.listprobes:
        result.AppendMessage("Copied listing script to clipboard... paste in Terminal. Will only list probes then exit")
    else:
        result.AppendMessage("Copied script to clipboard... paste in Terminal")


def generateDTraceScript(debugger, options):  
    headers = '#!/usr/sbin/dtrace -{}s'.format('e' if options.debug_with_clipboard else 'l' if options.listprobes else '')
    script = headers + '\n\n'
    if not options.not_quiet:
        script +=  '#pragma D option quiet\n'
    if options.destructive:
        script += '#pragma D option destructive\n'

    if options.flowindent:
        script += '#pragma D option flowindent\n'

    script += r'''dtrace:::BEGIN { printf("Starting... use Ctrl + c to stop\n"); }
dtrace:::END   { printf("Ending...\n"  ); }

/* Script content below */

''' 
    predicate = '/ {} /'.format(options.predicate) if options.predicate else ''
    script += '{}:{}:{}:{} {}'.format(options.provider, options.module, options.function, options.name, predicate)
    script += '''
{{
    {}
}}
'''.format(options.action)

    return script

def createOrTouchFilePath(filepath, dtrace_script):
    file = open(filepath, "w")
    file.write(dtrace_script)
    file.flush()
    st = os.stat(filepath)
    os.chmod(filepath, st.st_mode | S_IEXEC)
    file.close()

def generateOptionParser():
    usage = "usage: %prog [options]"
    parser = optparse.OptionParser(usage=usage, prog="tobjc")
    parser.add_option("-m", "--module",
                      action="store",
                      default="",
                      dest="module",
                      help="Specify the module i.e. objc$target:module::")

    parser.add_option("-f", "--function",
                      action="store",
                      default="",
                      dest="function",
                      help="Specify the module i.e. objc$target::function:")

    parser.add_option("-n", "--name",
                      action="store",
                      default="entry",
                      dest="name",
                      help="The name for the consumer i.e. objc$target:::name")

    parser.add_option("-g", "--debug",
                      action="store_true",
                      default=False,
                      dest="debug",
                      help="Display script to console output, and see if it compiles. This does NOT run the script")

    parser.add_option("-G", "--debug_with_clipboard",
                      action="store_true",
                      default=False,
                      dest="debug_with_clipboard",
                      help="Will copy contents to clipboard for dryrun testin")

    parser.add_option("-l", "--list_probes",
                      action="store_true",
                      default=False,
                      dest="listprobes",
                      help="List the probe count")

    parser.add_option("-d", "--provider",
                      action="store",
                      default="objc$target",
                      dest="provider",
                      help="The name of the provider i.e. provider:::")

    parser.add_option("-p", "--predicate",
                      action="store",
                      default=None,
                      dest="predicate",
                      help="Store the predicate. i.e. -p 'execname == \"launchd\"' will produce provider:module:function:name / execname == \"launchd\"")

    parser.add_option("-a", "--action",
                      action="store",
                      default='printf("0x%016p %c[%s %s]\\n", arg0, probefunc[0], probemod, (string)&probefunc[1]);',
                      dest="action",
                      help="Display script to console output")

    parser.add_option("-D", "--destructive",
                      action="store_true",
                      default=False,
                      dest="destructive",
                      help="Allow destructive actions in DTrace script")

    parser.add_option("-F", "--flowindent",
                      action="store_true",
                      default=False,
                      dest="flowindent",
                      help="Allow flowindent to DTrace script")

    parser.add_option("-Q", "--not_quiet",
                      action="store_true",
                      default=False,
                      dest="not_quiet",
                      help="Remove the quiet pragma option in DTrace script")

    return parser
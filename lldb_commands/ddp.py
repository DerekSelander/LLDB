# MIT License

# Copyright (c) 2020 Derik Ramirez

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
    'command script add -f ddp.handle_command ddp')

def handle_command(debugger, command, result, internal_dict):
    '''
    Displays the Document directories for the current app.
    This includes the DataDirectory and the Shared directories
    the app has access through from the shared groups.
    '''

    command_args = shlex.split(command, posix=True)
    parser = generateOptionParser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    if len(command_args) == 0 or command_args == ['-h']:
        parser.print_help()
    if options.data_directory or options.all_data_directories:
        result.AppendMessage("Data Dir:\n{}".format(getDocumentDirectory()))
    if options.all_data_directories:
        groups = getApplicationGroups()
        for i in groups:
            result.AppendMessage("group: {}\ndir: {}".format(i,getSharedDirForGroup(i)))
    if options.shared_directory:
        result.AppendMessage("Shared Dir for group: {}\n{}".format(options.shared_directory,getSharedDirForGroup(options.shared_directory)))
    if options.application_groups:
        result.AppendMessage("Application Groups:\n{}".format(getApplicationGroups()))

def executeCommand(command):
    debugger = lldb.debugger
    process = debugger.GetSelectedTarget().GetProcess()
    frame = process.GetSelectedThread().GetSelectedFrame()
    target = debugger.GetSelectedTarget()

    expr_options = lldb.SBExpressionOptions()
    expr_options.SetIgnoreBreakpoints(False);
    expr_options.SetFetchDynamicValue(lldb.eDynamicCanRunTarget);
    expr_options.SetTimeoutInMicroSeconds (30*1000*1000) # 30 second timeout
    expr_options.SetTryAllThreads (True)
    expr_options.SetUnwindOnError(False)
    expr_options.SetGenerateDebugInfo(True)
    expr_options.SetLanguage (lldb.eLanguageTypeObjC)
    expr_options.SetCoerceResultToId(True)
    return frame.EvaluateExpression(command, expr_options)

def getDocumentDirectory():
    command_script = r'''
    @import ObjectiveC;
    @import Foundation;
    [NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask][0].absoluteString;
    '''
    d_sbval = executeCommand(command_script)

    if d_sbval.error.fail:
        return str(d_sbval.error)
    return  d_sbval.description

def getSharedDirForGroup(group_name):
    command_script = r'''
    @import ObjectiveC;
    @import Foundation;
    [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"'''
    command_script += group_name + '"]'
    d_sbval = executeCommand(command_script)
    if d_sbval.error.fail:
        return str(d_sbval.error)
    return d_sbval.description

def getApplicationGroups():
    command_script = r'''
    @import ObjectiveC;
    @import Foundation;
    // Declare the private SecTask functions in your header file
    void* (SecTaskCopyValueForEntitlement)(void* task, CFStringRef entitlement, CFErrorRef  _Nullable *error);
    void* (SecTaskCreateFromSelf)(CFAllocatorRef allocator);

    // And call it in your code like this:
    CFErrorRef err = nil;
    NSArray* groups = (NSArray *)SecTaskCopyValueForEntitlement(SecTaskCreateFromSelf(NULL), CFSTR("com.apple.security.application-groups"), &err);

    groups;
    '''
    d_sbval = executeCommand(command_script)
    if d_sbval.error.fail:
            return []
    groups = []
    for i in range(d_sbval.GetNumChildren()):
        groups.append(d_sbval.GetChildAtIndex(i).description)
    return groups

def generateOptionParser():
    usage = "usage: %prog [options]"
    parser = optparse.OptionParser(usage=usage, prog="ddp")
    parser.add_option("-d", "--data_directory",
                      action="store_true",
                      default=False,
                      dest="data_directory",
                      help="Displays the Data Directory for the current app bundle.")
    parser.add_option("-a", "--all_data_directories",
                      action="store_true",
                      default=False,
                      dest="all_data_directories",
                      help="Displays the Data Directories for the current app bundle.")
    parser.add_option("-s", "--shared_directory",
                      action="store",
                      default=None,
                      dest="shared_directory",
                      help="Displays the Shared data directories the current app bundle has from its shared groups.")
    parser.add_option("-g", "--application_groups",
                      action="store_true",
                      default=False,
                      dest="application_groups",
                      help="Displays application_groups of the current app bundle.")
    return parser

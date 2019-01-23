#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lldb
import optparse
import shlex

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f taptap.taptap iblog')


def taptap(debugger, command, result, internal_dict):
    '''Help function here
    '''

    args = command.split()
    target = debugger.GetSelectedTarget()
    breakpointName = "DS_Tap_Breakpoint"
    if len(args) != 1:
        result.SetError("Expects either \"start\" or \"stop\" commands")
        return
    if args[0] == "start":
        bp_list = lldb.SBBreakpointList(target)
        target.FindBreakpointsByName(breakpointName, bp_list)
        if bp_list.GetSize() > 0:
            result.AppendMessage("IBAction logging already enabled")
            return

        breakpoint = target.BreakpointCreateByName("-[UIControl sendAction:to:forEvent:]")
        breakpoint.AddName(breakpointName)
    elif args[0] == "stop":
        bp_list = lldb.SBBreakpointList(target)
        target.FindBreakpointsByName(breakpointName, bp_list)
        for index in range(0, bp_list.GetSize()):
            bp = bp_list.GetBreakpointAtIndex(index)
            target.BreakpointDelete(bp.GetID())
        result.AppendMessage("Removed IBAction logging")
        return
    else:
        result.SetError("Expects either \"start\" or \"stop\" commands")
        return

    if not breakpoint.IsValid() or breakpoint.num_locations == 0:
        result.SetError("Unable to find -[UIControl sendAction:to:forEvent:]" + clean_command)
        return


    breakpoint.SetScriptCallbackFunction("taptap.breakpointHandler")
    result.AppendMessage("IBAction logging enabled")


def breakpointHandler(frame, bp_loc, dict):
    '''The function called when the breakpoint 
    gets triggered
    '''
        
    debugger = frame.GetThread().GetProcess().GetTarget().GetDebugger()
    debugger.HandleCommand('exp -l objc -O -- [[NSString alloc] initWithFormat:@"%@ (%p) -> %@.%s (%p)", (id)[(id)$arg1 class], $arg1, (id)[(id)$arg4 class], (char*)$arg3, $arg4]')
    # debugger.SetAsync(False)

    return False



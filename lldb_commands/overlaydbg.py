

import lldb
import os
import shlex
import optparse

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f overlaydbg.handle_command overlaydbg -h "Display UIDebuggingInformationOverlay on iOS"')

class GlobalProcess:
    hasPerformedSetup = False

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Toggles the UIDebuggingInformationOverlay, iOS 9.X - 11.X only
    '''

    target = exe_ctx.target
    if GlobalProcess.hasPerformedSetup is False:
        setupIfiOS11(target)
        debugger.HandleCommand('exp -lobjc -O -- [UIDebuggingInformationOverlay prepareDebuggingOverlay]')
        script = 'exp -lobjc -O -- id _dstap = [UIGestureRecognizer new]; [_dstap setState:3]; [[UIDebuggingInformationOverlayInvokeGestureHandler mainHandler] _handleActivationGesture:_dstap];  @"Displaying UIDebuggingInformationOverlay... resume execution"'
        debugger.HandleCommand(script)
        GlobalProcess.hasPerformedSetup = True
    else: 
        debugger.HandleCommand('exp -lobjc -O -- [[UIDebuggingInformationOverlay overlay] toggleVisibility]; [UIDebuggingInformationOverlay overlay] ?  @"Displaying UIDebuggingInformationOverlay... resume execution" : @"Failure, womp"')




def setupIfiOS11(target):
    options = lldb.SBExpressionOptions()
    options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    options.SetCoerceResultToId()

    versionval = target.EvaluateExpression('[[UIDevice currentDevice] systemVersion]', options)
    versionvalstr = versionval.description 

    if "11." in versionvalstr:
        tweakiOS11Memory(target, "UIKit")
    elif "12." in versionvalstr:
        tweakiOS11Memory(target, "UIKitCore")
    else:
        "print unknown version, exiting..."


def tweakiOS11Memory(target, moduleName):
    module = target.module[moduleName]

    symbolsFF = [ '__fetchedInternalDeviceOnceToken', 
                  'UIDebuggingOverlayIsEnabled.__overlayIsEnabled',
                  'UIDebuggingOverlayIsEnabled.onceToken',
                  '__isInternalDevice', 
                  '__UIGetDebuggingOverlayEnabledAssumingInternal.onceToken', 
                  '__hasCachedDebuggingOverlayEnabled', 
                  '__cachedDebuggingOverlayEnabled']

    for symStr in symbolsFF:
        syms = module.FindSymbols(symStr, lldb.eSymbolTypeData)
        for symbol in syms.symbols:
            loadAddr = symbol.GetStartAddress().GetLoadAddress(target)
            size = symbol.GetEndAddress().GetFileAddress() - symbol.GetStartAddress().GetFileAddress()
            debugger = target.GetDebugger()
            cmd = 'mem write {} 0x{} -s {}'.format(loadAddr, 'ff' * size, size)
            debugger.HandleCommand(cmd)


    syms = module.FindSymbols('__hasCachedDebuggingOverlayEnabled', lldb.eSymbolTypeData)
    for symbol in syms.symbols:
        loadAddr = symbol.GetStartAddress().GetLoadAddress(target)
        size = symbol.GetEndAddress().GetFileAddress() - symbol.GetStartAddress().GetFileAddress()
        debugger = target.GetDebugger()
        cmd = 'mem write {} 0xffffffffffffff01 -s 8'.format(loadAddr)
        debugger.HandleCommand(cmd)



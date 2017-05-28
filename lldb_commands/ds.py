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

# def __lldb_init_module(debugger, internal_dict):


def genExpressionOptions(useSwift=False, ignoreBreakpoints=False, useID=True):
    options = lldb.SBExpressionOptions()
    options.SetIgnoreBreakpoints(ignoreBreakpoints);
    options.SetFetchDynamicValue(lldb.eDynamicCanRunTarget);
    options.SetTimeoutInMicroSeconds (30*1000*1000) # 30 second timeout
    options.SetTryAllThreads (True)
    options.SetUnwindOnError(False)
    options.SetGenerateDebugInfo(True)
    if useSwift:
        options.SetLanguage (lldb.eLanguageTypeSwift)
    else:
        options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    options.SetCoerceResultToId(useID)
    return options

def getTarget(error=None):
    target = lldb.debugger.GetSelectedTarget()
    return target

def getFrame(error=None):
    frame = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
    # if frame is None and error is not None:
    #     pass # TODO
    return frame

def getSection(module=None, name=None):
    if module is None:
        path = getTarget().executable.fullpath
        module = getTarget().module[path]

    if name is None:
        return module.sections

    sections = name.split('.')
    index = 0
    if len(sections) == 0:
        return None
    section = module.FindSection(sections[0])
    while index < len(sections):
        name = sections[index]
        for subsec in section:
            if sections[index] in subsec.name:
                section = subsec
                if sections[-1] in subsec.name:
                    return subsec
                continue
        index += 1


    return None

def getDataFromSection(section):
    pass







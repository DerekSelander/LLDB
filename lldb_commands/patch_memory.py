

import lldb
import os
import argparse
from enum import Enum

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f patch_memory.handle_command mpatch -o -h "convenience for quick memory patches"')
    
def generate_arm64_mov_x0_shellcode(value):
    shellcode = bytearray()

    # Check if the value fits in 16 bits (movz can handle this case)
    if value <= 0xFFFF:
        # movz x0, #imm
        imm = value & 0xFFFF
        instr = 0xD2800000 | (imm << 5)  # Encoding of movz x0, #imm
        shellcode += instr.to_bytes(4, 'little')
    
    else:
        # Split value into 16-bit chunks and move into x0 using movz and movk
        # movz for the lower 16 bits, movk for higher 16 bits
        for shift in range(0, 64, 16):
            part = (value >> shift) & 0xFFFF
            if shift == 0:
                # movz x0, #imm
                instr = 0xD2800000 | (part << 5)  # movz x0, #part
            else:
                # movk x0, #imm, LSL #shift
                instr = 0xF2800000 | (part << 5) | ((shift // 16) << 21)  # movk x0, #part, LSL #(shift)
            
            shellcode += instr.to_bytes(4, 'little')

    shellcode += b'\xc0\x03\x5f\xd6' # ret opcode
    return shellcode

def try_parse_number(value):
    try:
        # Try interpreting the value as hexadecimal (with or without 0x prefix)
        return int(value, 16)
    except ValueError:
        try:
            # If it fails, try interpreting it as a decimal
            return int(value, 10)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid number: {value}")
    
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    mpatch [-a <address>|-n <symbol_name>]
    '''
    parser = generate_option_parser()
    try:
        args = parser.parse_args(command.split())
    except Exception as e:
        result.SetError(str(e))
        return
    
    error = lldb.SBError()
    target = exe_ctx.target
    
    if "x86_64" in target.GetTriple():
        result.SetError("x86_64 isn't supported")
        return
    
    shellcode = generate_arm64_mov_x0_shellcode(args.value)
    
    if args.address:
        target.process.WriteMemory(args.address, shellcode, error )
        result.AppendMessage("patched address {} to return {}".format(hex(args.address), hex(args.value)))
    elif args.module and args.symbol:
        result.SetError("TODO")
    elif args.symbol:
        functions = target.FindGlobalFunctions(args.symbol, 1, lldb.eMatchTypeNormal)
        if functions.GetSize() == 0:
            result.SetError("Couldn't find any symbols for \"{}\"".format(args.symbol))
            return
        symbol_context = functions.GetContextAtIndex(0) # for this particular case only do first hit
        symbol = symbol_context.GetSymbol()
        symbol_name = symbol.GetName()
        module = symbol_context.GetModule()
        module_name = module.GetFileSpec().GetFilename()
        start_addr = symbol.GetStartAddress()
        end_addr = symbol.GetEndAddress()
        resolved_addr = start_addr.GetLoadAddress(target)
        if resolved_addr:
            target.process.WriteMemory(resolved_addr, shellcode, error )
            if error.Fail():
                result.SetError("error : [ " + str(error.GetCString()) + " ]")
                return
            else:
                result.AppendMessage("patched {}`{} {} to return {}".format(module_name, symbol_name, hex(resolved_addr), hex(args.value)))
    else:
        result.SetError("mpatch requires either an -a,--address or -s,--symbol parameter")
        return

    # Uncomment if you are expecting at least one argument
    # clean_command = shlex.split(args[0])[0]


def generate_option_parser():
    parser = argparse.ArgumentParser(prog='mpatch', description='patch memory')
    parser.add_argument("-a", "--address",
                      type=lambda x:  try_parse_number(x),
                      dest="address",
                      help="Address to patch")
    parser.add_argument("-s", "--symbol",
                      dest="symbol",
                      help="symbol to patch")
    parser.add_argument("-r", "--regex-symbol",
                      type=lambda x:  try_parse_number(x),
                      dest="regex_symbol",
                      help="regex symbol to patch (likely multiple hits)")
    parser.add_argument("-m", "--module",
                      dest="module",
                      help="the module that the symbol should be searched in")
    parser.add_argument("-v", "--value",
                      type=lambda x:  try_parse_number(x),
                      dest="value",
                      help="return value")
    
    return parser
   



import lldb
import os
import shlex
import optparse
import ds

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f info.handle_command info -h "Get info about an address in memory"')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Documentation for how to use info goes here 
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return


    if len(args) != 1:
        result.SetError("Expects an address")
        return        

    if args[0].startswith("0x") or args[0].startswith("0X"):
        address = int(args[0], 16)
    else:
        address = int(args[0], 10)

    target = debugger.GetSelectedTarget()
    addr = target.ResolveLoadAddress(address)
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    returnDescription = ""
    foundAddress = False

    if addr.GetSection().IsValid():
        foundAddress, returnDescription = tryMachOAddress(addr, target, options)

    if foundAddress == False:
        foundAddress, returnDescription = tryHeapAddress(addr, target, options)


    if foundAddress:
        result.AppendMessage('{}'.format(returnDescription))
    else:
        result.SetError('Couldn\'t find info for address \'{}\''.format(addr))

    

def tryMachOAddress(addr, target, options):

    returnDescription = ""
    section = addr.GetSection()
    if not section.IsValid():
        return False, ""

    sectionName = section.GetName()
    tmpS = section 
    while tmpS.GetParent().IsValid():
        tmpS = tmpS.GetParent()
        sectionName = "{}.{}".format(tmpS.GetName(), sectionName)

    module = addr.GetModule()
    if module.IsValid():
        sectionName = ", {},{}".format(addr.GetModule().GetFileSpec().GetFilename(), sectionName)

    symbol = addr.GetSymbol()
    #  Is it a known function?
    if symbol.IsValid():
        returnDescription += "{}".format(symbol.GetName())
        startAddr = symbol.GetStartAddress()

        # Symbol address offset, if any
        addrOffset = addr.GetLoadAddress(target) - startAddr.GetLoadAddress(target)
        if addrOffset != 0:
            returnDescription += " + {}".format(addrOffset)

        # Mangled function
        if options.verbose:
            if symbol.GetMangledName():
                returnDescription += ", ({})".format(symbol.GetMangledName())

            returnDescription += ", External: {}".format("YES" if symbol.IsSynthetic() else "NO")

    tpe = target.GetBasicType(lldb.eBasicTypeNullPtr).GetPointerType()
    val = target.CreateValueFromAddress("__ds_unused", addr, tpe)
    if val.IsValid():
        data = val.GetData()
        k = ds.formatFromData(data, section, 1)
        # returnDescription += '{}'.format(k[1])


    returnDescription += sectionName
    return True, returnDescription




def tryHeapAddress(addr, target, options):
    returnDescription = ""
    cleanCommand = 'const void * ptr = (const void *){};'.format(addr.GetLoadAddress(target))
    cleanCommand += 'BOOL verboseMode = {};'.format("YES" if options.verbose else "NO")
    cleanCommand += r'''

#ifndef _MALLOC_MALLOC_H_

typedef struct _malloc_zone_t {
    void  *reserved1; 
    void  *reserved2; 
    size_t  (*size)(struct _malloc_zone_t *zone, const void *ptr); 
    void  *(*malloc)(struct _malloc_zone_t *zone, size_t size);
    void  *(*calloc)(struct _malloc_zone_t *zone, size_t num_items, size_t size); 
    void  *(*valloc)(struct _malloc_zone_t *zone, size_t size); 
    void  (*free)(struct _malloc_zone_t *zone, void *ptr);
    void  *(*realloc)(struct _malloc_zone_t *zone, void *ptr, size_t size);
    void  (*destroy)(struct _malloc_zone_t *zone); 
    const char  *zone_name;
    unsigned  (*batch_malloc)(struct _malloc_zone_t *zone, size_t size, void **results, unsigned num_requested); 
    void  (*batch_free)(struct _malloc_zone_t *zone, void **to_be_freed, unsigned num_to_be_freed); 
    struct malloc_introspection_t *introspect;
    unsigned  version;
    void *(*memalign)(struct _malloc_zone_t *zone, size_t alignment, size_t size);
    void (*free_definite_size)(struct _malloc_zone_t *zone, void *ptr, size_t size);
    size_t  (*pressure_relief)(struct _malloc_zone_t *zone, size_t goal);
} malloc_zone_t;

    extern malloc_zone_t* malloc_zone_from_ptr (   const void *  ptr  );
    extern size_t malloc_size  (   const void *  ptr  );
    extern size_t malloc_good_size(size_t size);

    extern const char* malloc_get_zone_name  (   malloc_zone_t *   zone   ) ;
#endif // _MALLOC_MALLOC_H_
    
    

    NSMutableString *retString;
    if (malloc_zone_from_ptr(ptr)) {

        retString = (NSString*)[[NSMutableString alloc] initWithFormat:@"heap pointer found in %s, (%d bytes)", malloc_get_zone_name(malloc_zone_from_ptr(ptr)), malloc_good_size(malloc_size(ptr))];

//*****************************************************************************/
#pragma mark - Ivars
//*****************************************************************************/
  
#define FAST_DATA_MASK          0x00007ffffffffff8UL

typedef struct ivar_t {
#if __x86_64__
    // *offset was originally 64-bit on some x86_64 platforms.
    // We read and write only 32 bits of it.
    // Some metadata provides all 64 bits. This is harmless for unsigned
    // little-endian values.
    // Some code uses all 64 bits. class_addIvar() over-allocates the
    // offset for their benefit.
#endif
    int32_t *offset;
    const char *name;
    const char *type;
    // alignment is sometimes -1; use alignment() instead
    uint32_t alignment_raw;
    uint32_t size;
    
  } ivar_t;
  
  
typedef struct ivar_list_t {
    uint32_t entsizeAndFlags;
    uint32_t count;
    ivar_t *first;
} ivar_list_t;

typedef struct class_ro_t {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
#ifdef __LP64__
    uint32_t reserved;
#endif
    
    const uint8_t * ivarLayout;
    
    const char * name;
    /* method_list_t   */ void * baseMethodList;
    /* protocol_list_t */ void * baseProtocols;
    ivar_list_t * ivars;
    uint8_t * weakIvarLayout;
    /* property_list_t */ void *baseProperties;
  
} class_ro_t;
  
  
typedef struct class_rw_t {
    uint32_t flags;
    uint32_t version;
    
    const class_ro_t *ro;
    
    /* method_array_t */ void* methods;        // redefined from method_array_t
    /* property_array_t */ void* properties;   // redefined from property_array_t
    /* protocol_list_t */ void* protocols;    // redefined from protocol_array_t
  
    struct dsobjc_class*   firstSubclass;
    struct dsobjc_class* nextSiblingClass;
    
    char *demangledName;
    
} class_rw_t;
  
  typedef struct dsobjc_class {
    struct dsobjc_class* isa;
    struct dsobjc_class* superclass;
    void *_buckets;             // formerly cache pointer and vtable
    uint32_t _mask;
    uint32_t _occupied;
    uintptr_t bits;
    
    class_rw_t *ds_data() {
      return (class_rw_t *)(bits & FAST_DATA_MASK);
    }
    
  } dsobjc_class;

      dsobjc_class *dsclass = (dsobjc_class*)object_getClass((id)ptr);
      if (dsclass) {
          (void)[retString appendString:(NSString*)[[NSString alloc] initWithFormat:@"\nin %@:\n", (id)NSStringFromClass((id)object_getClass((id)ptr))]];
          ivar_list_t *bivar = dsclass->ds_data()->ro->ivars;  
          if (bivar) {
            for (int i = 0; i < bivar->count; i++) {
                ivar_t *dsiv = (ivar_t *)(&bivar->first);

                int sz = dsiv[i].size;
                int32_t offset = *(int32_t *)dsiv[i].offset;
                char *baseAddr = (char *)ptr;
                char *dstype = (char *)dsiv[i].type;
                char *dsname = (char *)dsiv[i].name;

                // no clue what would be this size
                if (sz == 1) {
                  [retString appendString:(NSString*)[[NSString alloc] initWithFormat:@" %s %-30s\n\t%s\n", dstype, dsname, *((uint8_t *)(char *)ptr + (offset))]];
                  
                // no clue what would be this size
                } else if (sz == 2) {
                  [retString appendString:(NSString*)[[NSString alloc] initWithFormat:@" %s %-30s %p\n", dstype, dsname, *((uint16_t *)(char *)ptr + (offset))]];

                } else if (sz == 4) {
                      uint32_t* offsetAddr32 = *(uint32_t**)(baseAddr + offset);
                      if ((int)strcmp(dstype, "b1")==0 || (int)strcmp(dstype, "b2") ==0 ) {
                           // Its a bool
                          [retString appendString:(NSString*)[[NSString alloc] initWithFormat:@"+0x%-5x%s (%s): %s\n", offset, dsname, dstype,   *(BOOL*)(baseAddr + offset) ? "YES" : "NO"]];
                      } else {
                          [retString appendString:(NSString*)[[NSString alloc] initWithFormat:@"+0x%-5x%s (%s): 0x%012lx\n", offset, dsname, dstype,  offsetAddr32]];
                      }
                } else if (sz == 8) {
                    uint64_t* offsetAddr64 = *(uint64_t**)(baseAddr + offset);
                    NSMutableString *tmpType = nil;
                    if (dstype[0] == '@' && strlen(dstype) > 1) {
                        tmpType = (NSString*)[(NSString*)[(NSString*)[(NSString*)[NSString stringWithUTF8String:dstype] stringByReplacingOccurrencesOfString:@"@" withString:@""] stringByReplacingOccurrencesOfString:@"\"" withString:@""] stringByAppendingString:@"*"];
                    } else if (dstype[0] == '@') {
                        tmpType = @"id";
                    } else {
                        tmpType = (NSString*)[NSString stringWithUTF8String:dstype];
                    }

                    if (offsetAddr64) {

                       if ((char*)object_getClassName((id)offsetAddr64)) {
                           if (verboseMode) {
                             [retString appendString:(NSString*)[[NSString alloc] initWithFormat:@"+0x%-5x%s (%@): [0x%012lx] %@\n", offset, dsname, tmpType, offsetAddr64, (NSString*)[(id _Nullable)offsetAddr64 debugDescription] ]];
                           } else {
                             [retString appendString:(NSString*)[[NSString alloc] initWithFormat:@"+0x%-5x%s (%@): %@\n", offset, dsname, tmpType,  (NSString*)[(id _Nullable)offsetAddr64 debugDescription] ]];
                           }
                       } else {
                           [retString appendString:(NSString*)[[NSString alloc] initWithFormat:@"+0x%-5x%s (%@): 0x%012lx\n", offset, dsname, tmpType,  offsetAddr64]];
                       }
                    } else {
                       [retString appendString:(NSString*)[[NSString alloc] initWithFormat:@"+0x%-5x%s (%@): nil\n", offset, dsname, tmpType]];
                    }
                }

            }
        }
      }


    } else {
          retString = nil;
    }
    
// 0x00007ffffffffff8UL
    retString
    '''

    # lldb.debugger.HandleCommand("exp -l objc -- " + cleanCommand)
    # return False, returnDescription
    val = target.EvaluateExpression(cleanCommand, ds.genExpressionOptions())
    if val.GetValueAsUnsigned() == 0:
        return False, ""


    returnDescription += '{}'.format( val.description)



    return True, returnDescription



def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="info")
    parser.add_option("-v", "--verbose",
                      action="store_true",
                      default=None,
                      dest="verbose",
                      help="Use verbose amount of info")
    # parser.add_option("-c", "--check_if_true",
    #                   action="store_true",
    #                   default=False,
    #                   dest="store_true",
    #                   help="This is a placeholder option to show you how to use options with bools")
    return parser
    
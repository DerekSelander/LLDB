

import lldb
import os
import shlex
import optparse
import ds

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f lsof.handle_command lsof -h "lists open file descriptors in your program"')

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    '''
    Documentation for how to use lsof goes here 
    '''

    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    script = generateScript()
    interpreter = debugger.GetCommandInterpreter()
    res = lldb.SBCommandReturnObject()
    expression = interpreter.HandleCommand("exp -l objc -O -- " + script, res)

    if not res.Succeeded():
        result.SetError(res.GetError())

    result.AppendMessage(res.GetOutput())


def generateScript():
  script = r'''
  @import Foundation; 
#ifndef _SYS_PROC_INFO_H

struct vinfo_stat {
  uint32_t  vst_dev;  /* [XSI] ID of device containing file */
  uint16_t  vst_mode; /* [XSI] Mode of file (see below) */
  uint16_t  vst_nlink;  /* [XSI] Number of hard links */
  uint64_t  vst_ino;  /* [XSI] File serial number */
  uid_t   vst_uid;  /* [XSI] User ID of the file */
  gid_t   vst_gid;  /* [XSI] Group ID of the file */
  int64_t   vst_atime;  /* [XSI] Time of last access */
  int64_t   vst_atimensec;  /* nsec of last access */
  int64_t   vst_mtime;  /* [XSI] Last data modification time */
  int64_t   vst_mtimensec;  /* last data modification nsec */
  int64_t   vst_ctime;  /* [XSI] Time of last status change */
  int64_t   vst_ctimensec;  /* nsec of last status change */
  int64_t   vst_birthtime;  /*  File creation time(birth)  */
  int64_t   vst_birthtimensec;  /* nsec of File creation time */
  off_t   vst_size; /* [XSI] file size, in bytes */
  int64_t   vst_blocks; /* [XSI] blocks allocated for file */
  int32_t   vst_blksize;  /* [XSI] optimal blocksize for I/O */
  uint32_t  vst_flags;  /* user defined flags for file */
  uint32_t  vst_gen;  /* file generation number */
  uint32_t  vst_rdev; /* [XSI] Device ID */
  int64_t   vst_qspare[2];  /* RESERVED: DO NOT USE! */
};

struct vnode_info {
  struct vinfo_stat vi_stat;
  int     vi_type;
  int     vi_pad;
  fsid_t      vi_fsid;
};

struct proc_fdinfo {
  int32_t     proc_fd;
  uint32_t    proc_fdtype;  
};

struct vnode_info_path {
  struct vnode_info vip_vi;
  char      vip_path[1024]; /* tail end of it  */
};


struct proc_fileinfo {
  uint32_t    fi_openflags;
  uint32_t    fi_status;  
  off_t     fi_offset;
  int32_t     fi_type;
  uint32_t    fi_guardflags;
};

struct vnode_fdinfo {
  struct proc_fileinfo  pfi;
  struct vnode_info pvi;
};


struct vnode_fdinfowithpath {
  struct proc_fileinfo  pfi;
  struct vnode_info_path  pvip;
};

int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize);
int proc_pidfdinfo(int pid, int fd, int flavor, void * buffer, int buffersize);

#endif /*_SYS_PROC_INFO_H */

   int bufferSize = (int)proc_pidinfo(getpid(), 1, 0, 0, 0);
    struct proc_fdinfo *procFDInfo = (struct proc_fdinfo *)malloc(bufferSize);
    NSMutableString *retString = [NSMutableString string];
    
    bufferSize = (int)proc_pidinfo(getpid(), 1, 0, procFDInfo, bufferSize);
    
    int numberOfProcFDs = bufferSize / sizeof(struct proc_fdinfo);
    
    for (int i = 0; i < numberOfProcFDs; i++) {
        struct vnode_fdinfowithpath fdpath = {};
        struct proc_fdinfo *finfo = &procFDInfo[i];
        bufferSize = (int)proc_pidfdinfo(getpid(), finfo->proc_fd, 2, &fdpath, sizeof(struct vnode_fdinfowithpath));
        
        if (bufferSize < 0 || bufferSize < sizeof(struct vnode_fdinfo)) {
            continue;
        }
        
        [retString appendString:[NSString stringWithFormat:@"%d %s\n",  finfo->proc_fd, fdpath.pvip.vip_path]];

    }
  retString
  '''
  return script

def generate_option_parser():
    usage = "usage: %prog [options] TODO Description Here :]"
    parser = optparse.OptionParser(usage=usage, prog="lsof")
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
    
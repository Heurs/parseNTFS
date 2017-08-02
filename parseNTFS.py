import struct
import datetime
import os
import sys
import ctypes

global debug
global rootFile
global setRootFile
global mftCluster
global fdDisk
global clusterSize
global mftIdx
global mftSize
global mftEntries
global mftRecords
global mftEntryFromPath
global maxFileSize
global partitionOffset

mftSize = 0
maxFileSize = 0x8000000
rootFile = "C"
setRootFile = ""
clusterSize = 4096
partitionOffset = 0

verbose = 0

debug = False
# debug = True
mftIdx = {}
mftEntries = {}
mftRecords = {}
mftEntryFromPath = {}
fdDisk = None

if (len(sys.argv) < 3):
    print "+-------------------------------+"
    print "|      NTFS Crawler v0.1        |"
    print "+-------------------------------+"
    
    print "usage : parseNtfs.py [options]"
    print r"         -f suce.dmp                : Choice another file for root (c:) NTFS Header, not MBR"
    print r"         -ls c:5                    : List entries in MFT node 5 of c:"
    print r"         -ls c:\windows             : List entries in c:\windows"
    print r"         -lsd c:\windows            : List entries in MFT node 5"
    print r"         -indexOffset c:5           : Get hard-disk offset of node 5"
    print r"         -deleted                   : Found removed files but node already existing"
    print r"         -getFile c:1234 output.dll : Copy from NTFS datas node"
    print r"         -sz 0x1000000              : Set a maximum size for NTFS copy"
    print r"         -v                         : Verbose"
    sys.exit()

class WindowsTime:
    "Convert the Windows time in 100 nanosecond intervals since Jan 1, 1601 to time in seconds since Jan 1, 1970"
    def __init__(self, low, high):
        self.low = long(low)
        self.high = long(high)
        
        if (low == 0) and (high == 0):
            self.dt = 0
            self.dtstr = "Not defined"
            self.unixtime = 0
            return
        
        # Windows NT time is specified as the number of 100 nanosecond intervals since January 1, 1601.
        # UNIX time is specified as the number of seconds since January 1, 1970. 
        # There are 134,774 days (or 11,644,473,600 seconds) between these dates.
        self.unixtime = self.GetUnixTime()
              
        try:
            self.dt = datetime.datetime.utcfromtimestamp(self.unixtime)
            # Pass isoformat a delimiter if you don't like the default "T".
            self.dtstr = str(self.dt)
          
        except:
            self.dt = 0
            self.dtstr = "Invalid timestamp"
            self.unixtime = 0
          
        
    def GetUnixTime(self):
        t=float(self.high)*2**32 + self.low

     # The '//' does a floor on the float value, where *1e-7 does not, resulting in an off by one second error
     # However, doing the floor loses the usecs....
        return (t*1e-7 - 11644473600)
     #return((t//10000000)-11644473600)

def hexprint(string, no_print = False):
    result = ""
    if len(string) == 0:
        return
    ascii = list("."*256)
    for i in range(1,0x7f):
        ascii[i] = chr(i)
    ascii[0x0] = "."
    ascii[0x7] = "."
    ascii[0x8] = "."
    ascii[0x9] = "."
    ascii[0xa] = "."
    ascii[0x1b] = "."
    ascii[0xd] = "."
    ascii[0xff] = "\xfe"
    ascii = "".join(ascii)
    offset = 0
    while (offset+0x10) <= len(string):
        line = string[offset:(offset+0x10)]
        linebuf = " %08X " % offset
        for i in range(0,16):
            if i == 8:
                linebuf += " "
            linebuf += "%02X " % ord(line[i])
        linebuf += " "
        for i in range(0,16):
            linebuf += ascii[ord(line[i])]
        if no_print == True:
            result += linebuf+"\n"
        else:
            print linebuf
        offset += 0x10
    if (len(string) % 0x10) > 0:
        linebuf = " %08X " % offset
        for i in range((len(string)-(len(string) % 0x10)),(len(string))):
            if i == 8:
                linebuf += " "
            linebuf += "%02X " % ord(string[i])
        linebuf += "   "*(0x10-(len(string) % 0x10))
        linebuf += " "
        for i in range((len(string)-(len(string) % 0x10)),(len(string))):
            linebuf += ascii[ord(string[i])]
        if no_print == True:
            result += linebuf+"\n"
        else:
            print linebuf
    return result.decode("cp1252")


def raw_to_int(strNumber):
    result = 0
    i = 0
    while (i<len(strNumber)):
        result += ord(strNumber[i]) << (i*8)
        i += 1
    return result

def parse_little_endian_signed_positive(buf):
    ret = 0
    for i, b in enumerate(buf):
        ret += ord(b) * (1 << (i * 8))
    return ret

def parse_little_endian_signed_negative(buf):
    ret = 0
    for i, b in enumerate(buf):
        ret += (ord(b) ^ 0xFF) * (1 << (i * 8))
    ret += 1
        
    ret *= -1
    return ret

def parse_little_endian_signed(buf):
    try:
        if not ord(buf[-1]) & 0b10000000:
            return parse_little_endian_signed_positive(buf)
        else:
            return parse_little_endian_signed_negative(buf)
    except Exception:
        return ''

def quotechars( chars ):
       return ''.join( ['.', c][c.isalnum()] for c in chars )

def decodeATRHeader(s):
    d = {}
    d['type'] = struct.unpack("<L",s[:4])[0]
    if d['type'] == 0xffffffff:
        return d
    d['len'] = struct.unpack("<L",s[4:8])[0]
    d['res'] = struct.unpack("B",s[8])[0] # Non-resident flag
    d['nlen'] = struct.unpack("B",s[9])[0]
    d['name_off'] = struct.unpack("<H",s[10:12])[0]
    d['flags'] = struct.unpack("<H",s[12:14])[0]
    d['id'] = struct.unpack("<H",s[14:16])[0]
    if d['res'] == 0:
        d['ssize'] = struct.unpack("<L",s[0x10:0x14])[0]            # dwLength
        d['soff'] = struct.unpack("<H",s[0x14:0x16])[0]             # wAttrOffset
        d['idxflag'] = struct.unpack("B",s[0x16])[0]              # uchIndexedTag
        padding = struct.unpack("B",s[0x17])[0]                   # Padding
    else:
        d['start_vcn'] = struct.unpack("<Q",s[0x10:0x18])[0]    # n64StartVCN
        d['last_vcn'] = struct.unpack("<Q",s[0x18:0x20])[0]     # n64EndVCN
        d['run_off'] = struct.unpack("<H",s[0x20:0x22])[0]          # wDataRunOffset (in clusters, from start of partition?)
        d['compsize'] = struct.unpack("<H",s[0x22:0x24])[0]         # wCompressionSize
        padding = struct.unpack("<I",s[0x24:0x28])[0]               # Padding
        d['allocsize'] = struct.unpack("<Lxxxx",s[0x28:0x30])[0]    # n64AllocSize
        d['realsize'] = struct.unpack("<Lxxxx",s[0x30:0x38])[0]     # n64RealSize
        d['streamsize'] = struct.unpack("<Lxxxx",s[0x38:0x40])[0]   # n64StreamSize
        if d['nlen'] > 0:
            d['name'] = s[d['name_off']:d['name_off']+(d['nlen']*2)].decode('utf-16').encode('utf-8')
        else:
            d['name'] = ''
        (d['ndataruns'],d['dataruns'],d['drunerror']) = unpack_dataruns(s[d['run_off']:d['len']])

    return d

def decodeSIAttribute(s):
    d = {}
    d['crtime'] = WindowsTime(struct.unpack("<L",s[:4])[0],struct.unpack("<L",s[4:8])[0]).dtstr
    d['mtime'] = WindowsTime(struct.unpack("<L",s[8:0xc])[0],struct.unpack("<L",s[0xc:0x10])[0]).dtstr
    d['ctime'] = WindowsTime(struct.unpack("<L",s[0x10:0x14])[0],struct.unpack("<L",s[0x14:0x18])[0]).dtstr
    d['atime'] = WindowsTime(struct.unpack("<L",s[0x18:0x1c])[0],struct.unpack("<L",s[0x1c:0x20])[0]).dtstr
    d['dos'] = struct.unpack("<I",s[0x20:0x24])[0]          # 4
    d['maxver'] = struct.unpack("<I",s[0x24:0x28])[0]       # 4
    d['ver'] = struct.unpack("<I",s[0x28:0x2c])[0]          # 4
    d['class_id'] = struct.unpack("<I",s[0x2c:0x30])[0]     # 4
    d['own_id'] = struct.unpack("<I",s[0x30:0x34])[0]       # 4
    d['sec_id'] = struct.unpack("<I",s[0x34:0x38])[0]       # 4
    d['quota'] = struct.unpack("<d",s[0x38:0x40])[0]        # 8
    d['usn'] = struct.unpack("<d",s[0x40:0x48])[0]          # 8 - end of date to here is 40

    return d

def decodeFNAttribute(s, record):
    d = {}
    d['par_ref'] = struct.unpack("<Lxx", s[:6])[0]      # Parent reference nummber + seq number = 8 byte "File reference to the parent directory."
    d['par_seq'] = struct.unpack("<H",s[6:8])[0]        # Parent sequence number
    d['crtime'] = WindowsTime(struct.unpack("<L",s[8:0xc])[0],struct.unpack("<L",s[0xc:0x10])[0]).dtstr
    d['mtime'] = WindowsTime(struct.unpack("<L",s[0x10:0x14])[0],struct.unpack("<L",s[0x14:0x18])[0]).dtstr
    d['ctime'] = WindowsTime(struct.unpack("<L",s[0x18:0x1c])[0],struct.unpack("<L",s[0x1c:0x20])[0]).dtstr
    d['atime'] = WindowsTime(struct.unpack("<L",s[0x20:0x24])[0],struct.unpack("<L",s[0x24:0x28])[0]).dtstr
    d['alloc_fsize'] = struct.unpack("<q",s[0x28:0x30])[0]
    d['real_fsize'] = struct.unpack("<q",s[0x30:0x38])[0]
    d['flags'] = struct.unpack("<d",s[0x38:0x40])[0]            # 0x01=NTFS, 0x02=DOS
    d['nlen'] = struct.unpack("B",s[0x40])[0]
    d['nspace'] = struct.unpack("B",s[0x41])[0]

    bytes = s[0x42:0x42 + d['nlen']*2]
    try:
        d['name'] = bytes.decode('utf-16').encode('utf-8').lower()
    except:
        d['name'] = 'UnableToDecodeFilename'

    return d

def decodeIndexRoot(s):
    d = {}
    d['type'] = struct.unpack("<L", s[:4])[0]
    d['collection'] = struct.unpack("<L",s[4:8])[0]
    d['rec_size_byte'] = struct.unpack("<L",s[8:0xc])[0]
    d['rec_size_clust'] = struct.unpack("B",s[0xc])[0]
    # 3 bytes of padding
    d['off_start'] = struct.unpack("<L",s[0x10:0x14])[0]
    d['off_end_use'] = struct.unpack("<L",s[0x14:0x18])[0]
    d['off_end_alloc'] = struct.unpack("<L",s[0x18:0x1c])[0]
    d['flags'] = struct.unpack("<L",s[0x1c:0x20])[0]
    
    return d

def decodeReparsePoint(s):
    d = {}
    # 8 bytes of WTF
    d['full_path_size'] = struct.unpack("<H",s[0xc:0xe])[0]
    d['path_size'] = struct.unpack("<H",s[0xe:0x10])[0]
    
    # Not a good idea but not have the time to identify how it defined the offset
    offset = 0x10
    while offset < len(s) and s[offset:offset+4] != "\\\x00?\x00":
        offset += 4
    
    d['full_path'] = s[offset:offset+d['full_path_size']].decode('utf-16').encode('utf-8').lower()
    d['path'] = s[offset+d['full_path_size']:offset+d['full_path_size']+d['path_size']].decode('utf-16').encode('utf-8').lower()
    
    return d

def decodeIndex(s):
    d = {}
    # 8 bytes of WTF
    d['entry_len'] = struct.unpack("<H",s[8:0xa])[0]
    d['fn_len'] = struct.unpack("<H",s[0xa:0xc])[0]
    d['idx_flags'] = struct.unpack("<L",s[0xc:0x10])[0]
    
    return d

def decodeEaInfo(s):
    d = {}
    # 8 bytes of WTF
    # print s[:8]
    d['ea_packet_len'] = struct.unpack("<H",s[0:2])[0] # Size of the packed Extended Attributes
    d['len_ea'] = struct.unpack("<H",s[2:4])[0] # Number of Extended Attributes which have NEED_EA set
    d['unpack_ea_size'] = struct.unpack("<L",s[4:8])[0] # Size of the unpacked Extended Attributes
    
    return d

def decodeEa(s):
    
    result = []
    ptr = 0
    
    while (ptr+8) < len(s):
        d = {}
        d['next_ea_off'] = struct.unpack("<L",s[ptr+0:ptr+4])[0] # Offset to next Extended Attribute
        d['flags'] = struct.unpack("<B",s[ptr+4])[0] # Flags
        d['nlen'] = struct.unpack("<B",s[ptr+5])[0] # Name Length
        d['nval'] = struct.unpack("<H",s[ptr+6:ptr+8])[0] # Value Length
        d['name'] = s[ptr+8:ptr+8+d['nlen']]
        d['value'] = s[ptr+8+d['nlen']:ptr+8+d['nlen']+d['nval']]
        result.append(d)
        if (ptr+8+d['nlen']+d['nval']) > d['next_ea_off']:
            break
        ptr += d['next_ea_off']
    return result

def decodeAttributeList(s, record):
    hexFlag = False

    d = {}
    d['type'] = struct.unpack("<I",s[:4])[0]                # 4
    d['len'] = struct.unpack("<H",s[4:6])[0]                # 2
    d['nlen'] = struct.unpack("B",s[6])[0]                  # 1
    d['f1'] = struct.unpack("B",s[7])[0]                    # 1
    d['start_vcn'] = struct.unpack("<d",s[8:16])[0]         # 8
    d['file_ref'] = struct.unpack("<Lxx",s[16:22])[0]       # 6
    d['seq'] = struct.unpack("<H",s[22:24])[0]              # 2
    d['id'] = struct.unpack("<H",s[24:26])[0]               # 4
    
    bytes = s[26:26 + d['nlen']*2]
    d['name'] = bytes.decode('utf-16').encode('utf-8')

    return d

def decodeVolumeInfo(s):
    d = {}
    d['f1'] = struct.unpack("<d",s[:8])[0]                  # 8
    d['maj_ver'] = struct.unpack("B",s[8])[0]               # 1
    d['min_ver'] = struct.unpack("B",s[9])[0]               # 1
    d['flags'] = struct.unpack("<H",s[10:12])[0]            # 2
    d['f2'] = struct.unpack("<I",s[12:16])[0]               # 4

    if (debug):
        print "+Volume Info"
        print "++F1%d" % d['f1']
        print "++Major Version: %d" % d['maj_ver']
        print "++Minor Version: %d" % d['min_ver']
        print "++Flags: %d" % d['flags']
        print "++F2: %d" % d['f2']

    return d

# Decode a Resident Data Attribute
def decodeDataAttribute(s):
    d = {}
    
    d['dataSize'] = struct.unpack("<L",s[0x4:0x8])[0]
    d['non_resid_flag'] = struct.unpack("<B",s[0x8])[0] # Non-resident flag
    d['nlen'] = struct.unpack("<B",s[0x9])[0] # Name length
    d['name_off'] = struct.unpack("<H",s[0xa:0xc])[0] # Offset to the Name
    d['flags'] = struct.unpack("<H",s[0xc:0xe])[0] # Flags
    d['attrib_id'] = struct.unpack("<H",s[0xe:0x10])[0] # Attribute Id
    if d['non_resid_flag'] == 1:
        d['vcn_start'] = struct.unpack("<Q",s[0x10:0x18])[0]
        d['vcn_end'] = struct.unpack("<Q",s[0x18:0x20])[0]
        d['dataruns_offset'] = struct.unpack("<L",s[0x20:0x24])[0]
        if d['nlen'] == 0:
            d['attrib_name'] = ''
        else:
            d['attrib_name'] = s[d['name_off']:d['name_off']+(d['nlen']*2)].decode('utf-16').encode('utf-8')
        datas = unpack_dataruns(s[d['dataruns_offset']:d['dataSize']])
        d['numruns'] = datas[0]
        d['dataruns'] = datas[1]
        d['error'] = datas[2]
    elif d['non_resid_flag'] == 0:
        d['attrib_len'] = struct.unpack("<L",s[0x10:0x14])[0] # Length of the Attribute
        d['attrib_off'] = struct.unpack("<H",s[0x14:0x16])[0] # Offset to the Attribute
        d['indexed_flag'] = struct.unpack("<B",s[0x16])[0] # Indexed flag
        # 1 byte of padding
        d['attrib_name'] = s[0x18:0x18+(d['nlen']*2)].decode('utf-16').encode('utf-8')
        d['attrib_value'] = s[d['attrib_off']:d['attrib_off']+d['attrib_len']]
    
    return d
    
def ObjectID(s):
    objstr = ''
    if s == 0:
        objstr = 'Undefined'
    else:
        objstr = "%08x-%04x-%04x-%04x-%06x" % (raw_to_int(s[0:4]),raw_to_int(s[4:6]),
            raw_to_int(s[6:8]),raw_to_int(s[8:10]),raw_to_int(s[10:16]))

    return objstr

def decodeObjectID(s):
    d = {}
    d['objid'] = ObjectID(s[0:16])
    d['orig_volid'] = ObjectID(s[16:32])
    d['orig_objid'] = ObjectID(s[32:48])
    d['orig_domid'] = ObjectID(s[48:64])

    return d

def unpack_dataruns(str):
    # hexprint(str)
    dataruns = []
    
    lenOfRun = 0
    lcnElem = 0
    offset = 0
    while offset < len(str):
        sizeLen = (struct.unpack("<B", str[offset])[0] & 0xF)
        sizeOffset = (struct.unpack("<B", str[offset])[0] & 0xF0)>>4
        if sizeLen == 0:
            lenOfRun = 0
        else:
            lenOfRun = raw_to_int(str[offset+1:offset+1+sizeLen])
        if sizeOffset == 0:
            lcnElem += 0
        else:
            relativeLCN = raw_to_int(str[offset+1+sizeLen:offset+1+sizeLen+sizeOffset])
            if (relativeLCN & ((2**(8*sizeOffset))>>1)): # is negative ?
                relativeLCN = -((2**(8*sizeOffset))-relativeLCN)
            lcnElem += relativeLCN
            dataruns.append([lcnElem,lenOfRun])
        # print "sizeLen : %x" % sizeLen
        # print "relativeLCN : %x" % relativeLCN
        # print "lenOfRun : %x" % lenOfRun
        # print "lcnElem : %x (new : %x)" % (lcnElem,raw_to_int(str[offset+1+sizeLen:offset+1+sizeLen+sizeOffset]))
        offset += 1+sizeLen+sizeOffset
    numruns = len(dataruns)
    error = 0
    
    return numruns, dataruns, error

def decodeIndexHeader(s):
    hexFlag = False
    # File name attributes can have null dates.

    d = {}
    
    if s[:4] != "INDX":
        return d
    
    d['off_udp_seq'] = struct.unpack("<H", s[4:6])[0] # Offset to the Update Sequence
    d['size_udp'] = struct.unpack("<H", s[6:8])[0] * 2 # Size in words of the Update Sequence Number
    d['lf_num'] = struct.unpack("<Q", s[8:0x10])[0] # $LogFile sequence number
    d['vcn_idx'] = struct.unpack("<Q", s[0x10:0x18])[0] # VCN of this INDX buffer in the Index Allocation
    d['idx_entry_off'] = struct.unpack("<L", s[0x18:0x1c])[0] # Offset to the Index Entries (relative to 0x18)
    d['idx_size'] = struct.unpack("<L", s[0x1c:0x20])[0] # Size of Index Entries (relative to 0x18)
    d['idx_alloc_size'] = struct.unpack("<L", s[0x20:0x24])[0] # Allocated size of the Index Entries (relative to 0x18)
    d['is_not_leaf'] = struct.unpack("<B", s[0x24])[0] # 1 if not leaf node (b)
    # 3 bytes of padding
    d['udp_seq'] = struct.unpack("<H", s[0x28:0x2a])[0] # Update sequence
    if ((d['size_udp']-2)/2) > 0:
        d['upd_array'] = struct.unpack("<"+str((d['size_udp']/2)-1)+"H", s[0x2a:0x2a+(d['size_udp']-2)])
    else:
        d['upd_array'] = []
    
    return d

def decodeIndexRecord(s,idx_size):
    hexFlag = False
    # File name attributes can have null dates.
    
    blobFiles = {}
    offset = 0
    
    while (offset+0x52) < idx_size:
        d = {}
        
        d['mft_ref'] = raw_to_int(s[offset:offset+6]) # MFT Reference of the file
        d['mft_seq'] = raw_to_int(s[offset+6:offset+8]) # Sequence number
        d['idx_entry_size'] = struct.unpack("<H", s[offset+8:offset+0xa])[0] # Size of this index entry
        d['name_off'] = struct.unpack("<H", s[offset+0xa:offset+0xc])[0] # Offset to the filename
        d['idx_flags'] = struct.unpack("<H", s[offset+0xc:offset+0xe])[0] # Small Index / Large index
        # 2 bytes of padding
        d['mft_parent_ref'] = raw_to_int(s[offset+0x10:offset+0x16]) # MFT File Reference of the parent
        d['ctrime'] = WindowsTime(struct.unpack("<L",s[offset+0x18:offset+0x1c])[0],struct.unpack("<L",s[offset+0x1c:offset+0x20])[0]).dtstr # File creation time
        d['mtime'] = WindowsTime(struct.unpack("<L",s[offset+0x20:offset+0x24])[0],struct.unpack("<L",s[offset+0x24:offset+0x28])[0]).dtstr # Last modification time
        d['ctime'] = WindowsTime(struct.unpack("<L",s[offset+0x28:offset+0x2c])[0],struct.unpack("<L",s[offset+0x2c:offset+0x30])[0]).dtstr # Last modification time for FILE record
        d['atime'] = WindowsTime(struct.unpack("<L",s[offset+0x30:offset+0x34])[0],struct.unpack("<L",s[offset+0x34:offset+0x38])[0]).dtstr # Last access time
        d['file_size'] = struct.unpack("<Q", s[offset+0x38:offset+0x40])[0] # Allocated size of file
        d['file_size_real'] = struct.unpack("<Q", s[offset+0x40:offset+0x48])[0] # Real size of file
        d['file_flags'] = struct.unpack("<Q", s[offset+0x48:offset+0x50])[0] # File Flags
        d['fn_len'] = struct.unpack("<B", s[offset+0x50])[0] # Length of filename
        d['fn_namespace'] = struct.unpack("<B", s[offset+0x51])[0] # Length of filename
        try:
            d['name'] = s[offset+0x52:offset+0x52+(d['fn_len']*2)].decode('utf-16').encode('utf-8').lower()
        except:
            return d
        offset += 0x52+(d['fn_len']*2)
        if d['idx_flags'] == 1:
            # print "idx_flags !"
            offset += 8
        if (offset % 8) != 0:
            offset += 8-(offset % 8) # 8 bytes aling
        # print d
        if offset > idx_size:
            continue
        blobFiles[d['name']] = d
    
    return blobFiles

def getDirList(indx_datas):
    global clusterSize
    indx_blob = 0
    files = {}
    while indx_blob < len(indx_datas):
        indx_infos = decodeIndexHeader(indx_datas[indx_blob:])
        if len(indx_infos) == 0:
           indx_blob += clusterSize
           continue
        upd_offset = 0
        newIndexBuf = bytearray(indx_datas[indx_blob:])
        while upd_offset < ((indx_infos['size_udp']-2)/2) :
            newIndexBuf[(upd_offset*512)+512-1] = (indx_infos['upd_array'][upd_offset] & 0xff00)>>8
            newIndexBuf[(upd_offset*512)+512-2] = (indx_infos['upd_array'][upd_offset] & 0xff)
            upd_offset += 1
        curFiles = decodeIndexRecord(str(newIndexBuf)[0x18+indx_infos['idx_entry_off']:],indx_infos['idx_size']-indx_infos['idx_entry_off']+8)
        for curkey in curFiles.keys():
            if curFiles[curkey]['fn_namespace'] != 2 and not curkey.lower() in files.keys():
                files[curkey] = curFiles[curkey]
        indx_blob += clusterSize
    return files

def decodeMFTHeader(record, raw_record):
    record['magic'] = struct.unpack("<I", raw_record[:4])[0]
    record['upd_off'] = struct.unpack("<H",raw_record[4:6])[0]
    record['upd_cnt'] = struct.unpack("<H",raw_record[6:8])[0]
    record['lsn'] = struct.unpack("<d",raw_record[8:0x10])[0]
    record['seq'] = struct.unpack("<H",raw_record[0x10:0x12])[0]
    record['link'] = struct.unpack("<H",raw_record[0x12:0x14])[0]
    record['attr_off'] = struct.unpack("<H",raw_record[0x14:0x16])[0]
    record['flags'] = struct.unpack("<H", raw_record[0x16:0x18])[0]
    record['size'] = struct.unpack("<I",raw_record[0x18:0x1c])[0]
    record['alloc_sizef'] = struct.unpack("<I",raw_record[0x1c:0x20])[0]
    record['base_ref'] = struct.unpack("<Lxx",raw_record[0x20:0x26])[0]
    record['base_seq'] = struct.unpack("<H",raw_record[0x26:0x28])[0]
    record['next_attrid'] = struct.unpack("<H",raw_record[0x28:0x2a])[0]
    record['f1'] = raw_record[0x2a:0x2c]                            # Padding
    record['recordnum'] = struct.unpack("<I", raw_record[0x2c:0x30])[0]  # Number of this MFT Record
    record['seq_number'] = struct.unpack("<H",raw_record[0x30:0x32])[0]  # Sequence number
    if record['upd_off'] == 42:
        record['seq_attr1'] = raw_record[0x2c:0x2e]  # Sequence attribute for sector 1
        record['seq_attr2'] = raw_record[0x2e:0x3a]  # Sequence attribute for sector 2
    else:
        record['seq_attr1'] = raw_record[0x32:0x34]  # Sequence attribute for sector 1
        record['seq_attr2'] = raw_record[0x34:0x36]  # Sequence attribute for sector 2
    record['fncnt'] = 0                              # Counter for number of FN attributes
    record['datacnt'] = 0                            # Counter for number of $DATA attributes

def parse_record(raw_record, operation = "None"):
    record = {}
    record['filename'] = ''
    record['notes'] = ''
    record['ads'] = {}
    record['datacnt'] = 0
    
    clistFiles = {}
    
    if (not raw_record) or len(raw_record) < 1024:
        return record
    
    decodeMFTHeader(record, raw_record)

    if (record['seq_number'] == raw_record[0x1fe:0x200] and record['seq_number'] == raw_record[0x3fe:0x400]):
        raw_record = raw_record[:0x1fe]+record['seq_attr1']+raw_record[0x200:0x3fe]+record['seq_attr2']
    
    new_raw_record = bytearray(raw_record)
    new_raw_record[0x1fe] = record['seq_attr1'][0]
    new_raw_record[0x1ff] = record['seq_attr1'][1]
    new_raw_record[0x3fe] = record['seq_attr2'][0]
    new_raw_record[0x3ff] = record['seq_attr2'][1]
    raw_record = str(new_raw_record)
    
    record_number = record['recordnum']
    
    if debug:
        print '-->Record number: %d\n\tMagic: %s Attribute offset: %d Flags: %s Size:%d' % (record_number, record['magic'],
            record['attr_off'], hex(int(record['flags'])), record['size'])

    if record['magic'] == 0x44414142:
        if debug:
            print "BAAD MFT Record"
        record['baad'] = True
        return record

    if record['magic'] != 0x454c4946:
        if debug:
            print "Corrupt MFT Record"
        record['corrupt'] = True
        return record

    read_ptr = record['attr_off']
    listFiles = {}
    
    if record['size'] > 1024:
        record['size'] = 1024
    
    while (read_ptr < record['size']):

        ATRrecord = decodeATRHeader(raw_record[read_ptr:])
        
        if ATRrecord['type'] == 0xffffffff:             # End of attributes
            break

        if ATRrecord['nlen'] > 0:
            bytes = raw_record[read_ptr+ATRrecord['name_off']:read_ptr+ATRrecord['name_off'] + ATRrecord['nlen']*2]
            ATRrecord['name'] = bytes.decode('utf-16').encode('utf-8')
        else:
            ATRrecord['name'] = ''

        if debug:
            print "Attribute type: %x Length: %d Res: %x" % (ATRrecord['type'], ATRrecord['len'], ATRrecord['res'])

        if ATRrecord['type'] == 0x10:                   # Standard Information
            if debug:
                print "Stardard Information:\n++Type: %s Length: %d Resident: %s Name Len:%d Name Offset: %d" % \
                     (hex(int(ATRrecord['type'])),ATRrecord['len'],ATRrecord['res'],ATRrecord['nlen'],ATRrecord['name_off'])
            SIrecord = decodeSIAttribute(raw_record[read_ptr+ATRrecord['soff']:])
            record['si'] = SIrecord
            if debug:
                print "++CRTime: %s\n++MTime: %s\n++ATime: %s\n++EntryTime: %s" % \
                   (SIrecord['crtime'], SIrecord['mtime'], SIrecord['atime'], SIrecord['ctime'])

        elif ATRrecord['type'] == 0x20:                 # Attribute list
            if debug:
                print "Attribute list"
            if ATRrecord['res'] == 0:
                ALrecord = decodeAttributeList(raw_record[read_ptr+ATRrecord['soff']:], record)
                record['al'] = ALrecord
                if debug:
                    print "Name: %s"  % (ALrecord['name'])
            else:
                if debug:
                    print "Non-resident Attribute List?"
                record['al'] = None

        elif ATRrecord['type'] == 0x30:                 # File name
            if debug: print "File name record"
            FNrecord = decodeFNAttribute(raw_record[read_ptr+ATRrecord['soff']:], record)
            if not('fn' in record):
                record['fn'] = {}
            record['fn'] = record['fn'][record['fncnt']] = FNrecord
            if debug: print "Name: %s (%d)" % (FNrecord['name'],record['fncnt'])
            record['fncnt'] = record['fncnt'] + 1
            if FNrecord['crtime'] != 0:
                if debug: print "\tCRTime: %s MTime: %s ATime: %s EntryTime: %s" % (FNrecord['crtime'],
                        FNrecord['mtime'], FNrecord['atime'], FNrecord['ctime'])

        elif ATRrecord['type'] == 0x40:                 #  Object ID
            ObjectIDRecord = decodeObjectID(raw_record[read_ptr+ATRrecord['soff']:])
            record['objid'] = ObjectIDRecord
            if debug: print "Object ID"

        elif ATRrecord['type'] == 0x50:                 # Security descriptor
            record['sd'] = True
            if debug: print "Security descriptor"

        elif ATRrecord['type'] == 0x60:                 # Volume name
            record['volname'] = True
            if debug: print "Volume name"

        elif ATRrecord['type'] == 0x70:                 # Volume information
            if debug: print "Volume info attribute"
            VolumeInfoRecord = decodeVolumeInfo(raw_record[read_ptr+ATRrecord['soff']:])
            record['volinfo'] = VolumeInfoRecord

        elif ATRrecord['type'] == 0x80:                 # Data
            DataAttribute = decodeDataAttribute(raw_record[read_ptr:])
            if DataAttribute['attrib_name'] == '':
                record['data'] = DataAttribute
            else:
                record['ads'][DataAttribute['attrib_name']] = DataAttribute
            record['datacnt'] = record['datacnt'] + 1
            
            if debug: print "Data attribute"

        elif ATRrecord['type'] == 0x90:                 # Index root
            record['indexroot'] = decodeIndexRoot(raw_record[read_ptr+ATRrecord['soff']:])
            if (operation == "DIR" or operation == "FILE"):
                if record['indexroot']['flags'] == 1: # Child node exist
                    cOffset = record['indexroot']['off_start']
                    baseOffset = read_ptr+ATRrecord['soff']+0x10 # 0x10 is size of Attrib header
                    
                    while cOffset < record['indexroot']['off_end_alloc']:
                        cIndex = decodeIndex(raw_record[baseOffset+cOffset:])
                        if debug:
                            if (cIndex['idx_flags'] & 1):
                                print "    + Entry has a child"
                            if (cIndex['idx_flags'] & 2):
                                print "    + Last entry"
                        cOffset += cIndex['entry_len']
                clistFiles = decodeIndexRecord(raw_record[read_ptr+ATRrecord['soff']+0x20:],ATRrecord['ssize']-0x20)
                for ckey in clistFiles.keys():
                    if clistFiles[ckey]['fn_namespace'] != 2:
                        listFiles[ckey] = clistFiles[ckey]
                
            record['indexroot'] = ATRrecord
            if debug: print "Index root"

        elif ATRrecord['type'] == 0xA0:                 # Index allocation
            record['indexallocation'] = ATRrecord
            if (operation == "DIR" or operation == "FILE"):
                if ATRrecord['res'] == 1: # Non resident datas
                    parsedSize = 0
                    for clust_index, idxSz in ATRrecord['dataruns']:
                        if parsedSize < ATRrecord['allocsize']:
                            parsedSize += (idxSz * clusterSize)
                            index_offset = clust_index * clusterSize
                            if idxSz > 0x8000:
                                # print "LIMIT!"
                                # sys.exit()
                                continue
                            indx_datas = getRawDatas(index_offset,idxSz * clusterSize)
                            clistFiles = getDirList(indx_datas)
                            for ckey in clistFiles.keys():
                                listFiles[ckey] = clistFiles[ckey]
                        else:
                            idxSz = ATRrecord['allocsize'] - parsedSize
                            index_offset = clust_index * clusterSize
                            if idxSz > 0x1000000:
                                # print "LIMIT!"
                                # sys.exit()
                                continue
                            indx_datas = getRawDatas(index_offset,idxSz)
                            clistFiles = getDirList(indx_datas)
                            for ckey in clistFiles.keys():
                                listFiles[ckey] = clistFiles[ckey]
                            parsedSize += ATRrecord['allocsize'] - parsedSize

        elif ATRrecord['type'] == 0xB0:                 # Bitmap
            record['bitmap'] = True
            if debug: print "Bitmap"

        elif ATRrecord['type'] == 0xC0:                 # Reparse point
            record['reparsepoint'] = True
            target = decodeReparsePoint(raw_record[read_ptr+ATRrecord['soff']:read_ptr+ATRrecord['soff']+ATRrecord['len']])
            record['reparsepoint_dest'] = target
            if debug: print "Reparse point"

        elif ATRrecord['type'] == 0xD0:                 # EA Information
            # record['eainfo'] = True
            record['eainfo'] = decodeEaInfo(raw_record[read_ptr+ATRrecord['soff']:read_ptr+ATRrecord['soff']+ATRrecord['len']])
            if debug: print "EA Information"

        elif ATRrecord['type'] == 0xE0:                 # EA
            # record['ea'] = True
            
            if ATRrecord['res'] == 1: # is a non-resident data store ?
                datas = getDatasFromAttribute(ATRrecord)
            else:
                datas = raw_record[read_ptr+ATRrecord['soff']:read_ptr+ATRrecord['len']]
            record['ea'] = decodeEa(datas)
            if debug: print "EA"

        elif ATRrecord['type'] == 0xF0:                 # Property set
            record['propertyset'] = True
            if debug: print "Property set"

        elif ATRrecord['type'] == 0x100:                 # Logged utility stream
            record['loggedutility'] = True
            if debug: print "Logged utility stream"

        else:
            if debug: print "Found an unknown attribute"

        if ATRrecord['len'] > 0:
            read_ptr = read_ptr + ATRrecord['len']
        else:
            if debug: print "ATRrecord->len < 0, exiting loop"
            break
    if operation == "DIR" and not 'reparsepoint' in record:
        return listFiles
    return record

def init():
    global fdDisk
    global clusterSize
    global mftCluster
    global setRootFile
    global partitionOffset
    
    try:
        if setRootFile == "":
            fdDisk = open("\\\\.\\"+rootFile+":", "rb")
        else:
            fdDisk = open(setRootFile, "rb")
    except:
        print "[!] Device \\\\.\\"+rootFile+": isn't accessible"
        sys.exit()
    dump = fdDisk.read(512)
    
    if "Invalid partition table" in dump:
        # This is a MBR and not VBR
        partitionOffset = struct.unpack("L",dump[0x1c6:0x1ca])[0] * 512
        fdDisk.seek(partitionOffset)
        dump = fdDisk.read(512)

    if dump[0x10:0x13] != "\x00\x00\x00":
        print "BAD Sector !"
        sys.exit()
    sectorSize = struct.unpack("H",dump[0xb:0xd])[0]
    sectorPerCluster = struct.unpack("b",dump[0xd:0xe])[0]
    sectorsPerTrack = struct.unpack("H",dump[0x18:0x1a])[0]
    nbHead = struct.unpack("H",dump[0x1a:0x1c])[0]
    hiddenSectors = struct.unpack("L",dump[0x1c:0x20])[0]
    totalSectors = struct.unpack("Q",dump[0x28:0x30])[0]
    mftCluster = struct.unpack("Q",dump[0x30:0x38])[0]
    mftMirrCluster = struct.unpack("Q",dump[0x38:0x40])[0]
    clusterPerFilerecordSegment = struct.unpack("L",dump[0x40:0x44])[0]
    clusterPerIndexBuffer = struct.unpack("b",dump[0x44:0x45])[0]

    clusterSize = (sectorSize*sectorPerCluster)

    # print " + Bytes per sector : "+str(sectorSize)
    # print " + Sectors per Cluser : "+str(sectorPerCluster)
    # print " + Sector per track : "+str(sectorsPerTrack)
    # print " + Number of Head : "+str(nbHead)
    # print " + Hidden sectors : "+str(hiddenSectors)
    # print " + Number of sectors : "+str(totalSectors)
    # print " + $MFT Index : "+hex(mftCluster)

global mftMap
mftMap = []

def printDetails(parserEntry, level = 1):
    if level > 3:
        print ('  '*level)+"  - (...)"
        return
    
    if type(parserEntry) == dict:
        for key in sorted(parserEntry.keys()):
            if type(parserEntry[key]) == dict:
                print ('  '*level)+"  - "+str(key)+" :"
                try:
                    printDetails(parserEntry[key], level + 1)
                except:
                    print ('  '*level)+"  - "+key+" : "+str(parserEntry[key])
            else:
                print ('  '*level)+"  - "+key+" : "+str(parserEntry[key])
    elif type(parserEntry) == list:
        for key in sorted(parserEntry):
            if type(key) == dict:
                print ('  '*level)+"  - "+str(key)+" :"
                try:
                    printDetails(key, level + 1)
                except:
                    print ('  '*level)+"  - "+key+" : "+str(key)
            else:
                print ('  '*level)+"  - "+key+" : "+str(key)

def seekIndex(idx,getOffset = False):
    global fdDisk
    global mftCluster
    global clusterSize
    global mftMap
    global mftSize
    global partitionOffset
    
    if fdDisk == None:
        init()
    
    if mftMap == []:
        fdDisk.seek(partitionOffset + (mftCluster*clusterSize), os.SEEK_SET)
        dump = fdDisk.read(1024)
        mftInfos = parse_record(dump)
        mftMap = mftInfos['data']['dataruns']
        for fileChunkOffset, chunkSize in mftMap:
            mftSize += (chunkSize * clusterSize)
    idxOffset = idx * 1024
    realOffset = 0
    mft_offset = 0
    for fileChunkOffset, chunkSize in mftMap:
        if idxOffset < (mft_offset+(chunkSize*clusterSize)) and idxOffset >= mft_offset:
            realOffset += (fileChunkOffset*clusterSize) + (idxOffset-mft_offset)
            break
        mft_offset += (chunkSize*clusterSize)
    if getOffset == True:
        # print "Real Offset of 0x%x : 0x%x" % (idx,realOffset)
        return realOffset
    fdDisk.seek(partitionOffset + realOffset, os.SEEK_SET)

def getRawDatas(offset, size):
    global fdDisk
    global partitionOffset
    try:
        fdDisk.seek(partitionOffset + offset, os.SEEK_SET)
        if size < maxFileSize:
            dump = fdDisk.read(size)
        else:
            dump = fdDisk.read(maxFileSize)
        return dump
    except:
        return ""

def getEntry(idx):
    global fdDisk
    seekIndex(idx)
    dump = fdDisk.read(1024)
    return dump

def getRecordFromIndex(index):
    if index in mftRecords:
        return mftRecords[index]
    dump = getEntry(index)
    mftRecords[index] = parse_record(dump)
    return mftRecords[index]

def getNodeFromPath(path,node=5):
    path = path.lower()
    if path[-1] == "\\":
        path = path[:-1]
    if path in mftEntryFromPath:
        return mftEntryFromPath[path]
    spath = path.split("\\")
    if len(spath[0]) == 0:
        return node
    index = 0
    if spath[0][-1] == ':':
        if len(spath) < 2 or spath[1] == '':
            return 5
        else:
            index = 1
    cpath = spath[index]
    dump = getEntry(node)
    files = parse_record(dump,"DIR")
    if cpath.lower() in files:
        if len(spath) > (index+1):
            destNode = getNodeFromPath("\\".join(spath[index+1:]),files[cpath.lower()]['mft_ref'])
            if node == 5:
                mftEntryFromPath[path] = destNode
            return destNode
        else:
            destNode = files[cpath.lower()]['mft_ref']
            if node == 5:
                mftEntryFromPath[path] = destNode
            return destNode
    else:
        return -1

def printMftEntry(objfile):
    strResult = ""
    
    if 'fn' in objfile:
        file = objfile['fn']
        if 'indexroot' in objfile:
            file['file_flags'] = 0x10000000
        else:
            file['file_flags'] = 0
        file['file_size'] = file['real_fsize']
        file['mft_ref'] = objfile['recordnum']
    else:
        file = objfile
    if file['mtime'] == 'Not defined':
        file['mtime'] = "0000-00-00 00:00:00"
    if file['file_flags'] & 0x10000000:
        strResult += "<DIR> "+file['mtime'][:19]+" "+("%13d" % (file['file_size']))+" "+file['name']+" ("+str(file['mft_ref'])+")"#+" "+str(file['mft_parent_ref'])
    else:
        strResult += "      "+file['mtime'][:19]+" "+("%13d" % (file['file_size']))+" "+file['name']+" ("+str(file['mft_ref'])+")"#+" "+str(file['mft_parent_ref'])
    dump = getEntry(file['mft_ref'])
    ccfile = parse_record(dump)
    for cads in ccfile['ads']:
        strResult += "\n<ADS>                                   "+file['name']+":"+cads
    return strResult

def listFromNode(node):
    dump = getEntry(node)
    files = parse_record(dump,"DIR")
    delFiles = []
    if node in mftEntries:
        delFiles = mftEntries[node]
    
    if ('fn' in files) and ('reparsepoint_dest' in files):
        print "<LNK> "+files['fn']['name']+" -> "+str(files['reparsepoint_dest']['path'])
        return
    for cfile in sorted(files.keys()):
        strEntry = printMftEntry(files[cfile])
        print strEntry
    for cdelFile, cdelNode in delFiles:
        if "~" in cdelFile:
            continue
        if not cdelFile in files.keys():
            print "<DEL> "+files[cfile]['mtime'][:19]+" "+("%13d" % (files[cfile]['file_size']))+" "+cdelFile+" ("+str(cdelNode)+")"#+" "+str(files[cfile]['mft_parent_ref'])

def getMftParentRef(mftBlob):
    if mftBlob[:4] != "FILE":
        return -1
    coff = 0x38
    
    recordSize = struct.unpack("<L",mftBlob[0x1c:0x20])[0]
    while (coff < recordSize) and (coff < 1024):
        if mftBlob[coff:coff+4] != "\x30\x00\x00\x00":
            coff += struct.unpack("<L",mftBlob[coff+4:coff+8])[0]
            if mftBlob[coff:coff+4] == "\xFF\xFF\xFF\xFF" or coff == 0:
                return -1
            continue
        return struct.unpack("<L",mftBlob[coff+0x18:coff+0x1c])[0]
    return -1

def isDeletedNode(mftBlob):
    if mftBlob[:4] != "FILE":
        return -1
    flags = struct.unpack("<H",mftBlob[0x16:0x18])[0]
    if flags == 0:
        return True
    return False

def getParentPath(parentNode):
    parentPath = ""
    parentList = []
    while parentNode != -1:
        if parentNode == 5:
            parentPath = "c:\\"+parentPath
            break
        if parentNode in parentList:
            parentPath = "...\\"+parentPath
            break
        parentList.append(parentNode)
        file = getRecordFromIndex(parentNode)
        if 'fn' in file:
            parentPath = file['fn']['name']+"\\"+parentPath
            parentNode = file['fn']['par_ref']
        else:
            parentPath = "...\\"+parentPath
            break
    return parentPath

def getDeletedFiles():
    global clusterSize
    
    seekIndex(0)
    sizeOfChunkCopy = 0x1000000
    
    globOffset = 0
    seekOffset = 0
    
    for hdOffset, hdSize in mftMap:
        hdSize = hdSize * clusterSize
        hdOffset = hdOffset * clusterSize
        coffset = 0
        seekIndex(globOffset/1024)
        while (coffset+sizeOfChunkCopy) < (hdSize):
            # print "seekOffset = %x" % seekOffset
            seekIndex((globOffset+coffset)/1024)
            dump = fdDisk.read(sizeOfChunkCopy)
            ccoffset = 0
            while ccoffset < len(dump):
                if isDeletedNode(dump[ccoffset:ccoffset+1024]):
                    cobj = parse_record(dump[ccoffset:ccoffset+1024])
                    if 'fn' in cobj:
                        strEntry = printMftEntry(cobj)
                        print strEntry
                ccoffset += 1024
                seekOffset += 1024
            coffset += len(dump)
        if coffset < (hdSize):
            seekIndex((globOffset+coffset)/1024)
            dump = fdDisk.read(hdSize-coffset)
            ccoffset = 0
            while ccoffset < len(dump):
                if isDeletedNode(dump[ccoffset:ccoffset+1024]):
                    cobj = parse_record(dump[ccoffset:ccoffset+1024])
                    if 'fn' in cobj:
                        strEntry = printMftEntry(cobj)
                        print strEntry
                ccoffset += 1024
                seekOffset += 1024
            coffset += len(dump)
        globOffset += hdSize
    return mftEntries

def getMftList(node):
    global clusterSize
    
    seekIndex(0)
    sizeOfChunkCopy = 0x1000000
    
    globOffset = 0
    seekOffset = 0
    
    if not node in mftEntries:
        mftEntries[node] = []
    
    for hdOffset, hdSize in mftMap:
        hdSize = hdSize * clusterSize
        hdOffset = hdOffset * clusterSize
        coffset = 0
        seekIndex(globOffset/1024)
        while (coffset+sizeOfChunkCopy) < (hdSize):
            seekIndex((globOffset+coffset)/1024)
            dump = fdDisk.read(sizeOfChunkCopy)
            ccoffset = 0
            while ccoffset < len(dump):
                if getMftParentRef(dump[ccoffset:ccoffset+1024]) == node:
                    cobj = parse_record(dump[ccoffset:ccoffset+1024])
                    if 'fn' in cobj:
                        mftEntries[node].append([cobj['fn']['name'].lower(), ((globOffset+coffset+ccoffset)/1024)])
                ccoffset += 1024
                seekOffset += 1024
            coffset += len(dump)
        if coffset < (hdSize):
            seekIndex((globOffset+coffset)/1024)
            dump = fdDisk.read(hdSize-coffset)
            ccoffset = 0
            while ccoffset < len(dump):
                if getMftParentRef(dump[ccoffset:ccoffset+1024]) == node:
                    cobj = parse_record(dump[ccoffset:ccoffset+1024])
                    if 'fn' in cobj:
                        mftEntries[node].append([cobj['fn']['name'].lower(), ((globOffset+coffset+ccoffset)/1024)])
                ccoffset += 1024
                seekOffset += 1024
            coffset += len(dump)
        globOffset += hdSize
    return mftEntries

def listFromPath(path):
    if not path in mftEntryFromPath:
        node = getNodeFromPath(path)
        mftEntryFromPath[path] = node
    else:
        node = mftEntryFromPath[path]
    if node <= 0:
        print path+" is not accessible"
        sys.exit()
    listFromNode(node)

def dumpFile(node, outputFile, ads = ""):
    global maxFileSize
    seekIndex(node)
    dump = fdDisk.read(1024)
    fileInfos = parse_record(dump)
    if ads == "":
        if 'data' in fileInfos:
            dump = getDatasFromAttribute(fileInfos['data'])
            try:
                destFile = open(outputFile,"wb")
            except:
                print outputFile+" not exist :-("
                sys.exit()
            destFile.write(dump)
            destFile.close()
            print str(len(dump))+" write in "+outputFile
        else:
            if fileInfos['fn']['alloc_fsize'] == 0:
                print "Size of the file is 0."
            else:
                print "[!] No datas accessible"
    else:
        if 'ads' in fileInfos:
            dump = getDatasFromAttribute(fileInfos['ads'][ads])
            try:
                destFile = open(outputFile,"wb")
            except:
                print outputFile+" not exist :-("
                sys.exit()
            destFile.write(dump)
            destFile.close()
            print str(len(dump))+" write in "+outputFile

def getDatasFromAttribute(fn_attrib):
    dump = ""
    
    if 'dataruns' in fn_attrib:
        copySize = 0
        for offset, size in fn_attrib['dataruns']:
            fdDisk.seek(partitionOffset + (offset*clusterSize), os.SEEK_SET)
            if maxFileSize < (copySize + (size * clusterSize)):
                dump += fdDisk.read(maxFileSize-copySize)
                break
            dump += fdDisk.read(size * clusterSize)
            copySize += size * clusterSize
    elif 'attrib_value' in fn_attrib:
        dump = fn_attrib['attrib_value']
    
    return dump

curr_opt = 1

while (curr_opt < len(sys.argv)) and (sys.argv[curr_opt][0] == '-'):
    if (sys.argv[curr_opt] == '-ls'):
        curr_opt += 1
        if len(sys.argv[curr_opt]) < 3:
            print sys.argv[curr_opt]+" isn't a correct argument"
            sys.exit()
        if sys.argv[curr_opt][1] != ":":
            print sys.argv[curr_opt]+" isn't a correct argument"
            sys.exit()
        rootFile = sys.argv[curr_opt][0]
        if sys.argv[curr_opt][2] == "\\":
            listFromPath(sys.argv[curr_opt].lower())
        else:
            try:
                node = int(sys.argv[curr_opt][2:],0)
            except:
                print sys.argv[curr_opt]+" isn't a correct argument"
                sys.exit()
            listFromNode(node)
    elif (sys.argv[curr_opt] == '-lsd'):
        curr_opt += 1
        if len(sys.argv[curr_opt]) < 3:
            print sys.argv[curr_opt]+" isn't a correct argument"
            sys.exit()
        if sys.argv[curr_opt][1] != ":":
            print sys.argv[curr_opt]+" isn't a correct argument"
            sys.exit()
        rootFile = sys.argv[curr_opt][0]
        if sys.argv[curr_opt][2] == "\\":
            prevNode = getNodeFromPath(sys.argv[curr_opt].lower())
            getMftList(prevNode)
            listFromPath(sys.argv[curr_opt].lower())
        else:
            try:
                node = int(sys.argv[curr_opt][2:],0)
            except:
                print sys.argv[curr_opt]+" isn't a correct argument"
                sys.exit()
            getMftList(node)
            listFromNode(node)
    elif (sys.argv[curr_opt] == '-v'):
        verbose = 1
    elif (sys.argv[curr_opt] == '-f'):
        curr_opt += 1
        setRootFile = sys.argv[curr_opt]
    elif (sys.argv[curr_opt] == '-indexOffset'):
        curr_opt += 1
        if sys.argv[curr_opt][1] != ":":
            print sys.argv[curr_opt]+" isn't a correct argument"
            sys.exit()
        rootFile = sys.argv[curr_opt][0]
        offset = seekIndex(int(sys.argv[curr_opt].split(":")[1],0),True)
        print "MFT node offset : 0x%x" % offset
        fdDisk.seek(partitionOffset + offset, os.SEEK_SET)
        nodeDump = fdDisk.read(1024)
        hexprint(nodeDump)
        printDetails(getRecordFromIndex(int(sys.argv[curr_opt].split(":")[1],0)))
        sys.exit()
    elif (sys.argv[curr_opt] == '-deleted'):
        curr_opt += 1
        if sys.argv[curr_opt][1] != ":":
            print sys.argv[curr_opt]+" isn't a correct argument"
            sys.exit()
        rootFile = sys.argv[curr_opt][0]
        getDeletedFiles()
    elif (sys.argv[curr_opt] == '-sz'):
        curr_opt += 1
        maxFileSize = int(sys.argv[curr_opt],0)
    elif (sys.argv[curr_opt] == '-getFile'):
        curr_opt += 1
        if len(sys.argv) < 4:
            print "Too few arguments"
            sys.exit()
        if len(sys.argv[curr_opt]) < 3:
            print sys.argv[curr_opt]+" isn't a correct argument"
            sys.exit()
        if sys.argv[curr_opt][1] != ":":
            print sys.argv[curr_opt]+" isn't a correct argument"
            sys.exit()
        rootFile = sys.argv[curr_opt][0]
        fileNode = sys.argv[curr_opt][2:]
        if ":" in fileNode:
            dumpFile(int(fileNode.split(":")[0],0),sys.argv[curr_opt+1],fileNode.split(":")[1])
        else:
            dumpFile(int(fileNode,0),sys.argv[curr_opt+1])
    curr_opt += 1



import binaryninja as bn
from binaryninja import LowLevelILOperation
import struct

#====================#
#    AoB Scanner     #
#====================#

def aob_scan(bv, pattern, execute_only = True):

    # init patern vars
    raw = pattern.split(' ')
    mask = [False] * len(raw)
    sign = [None] * len(raw)
    
    # populate vars
    for i in range(0, len(raw)):
        if raw[i] != "??":
            mask[i] = True
            sign[i] = int(raw[i],16)
    
    # scan
    results = [];
    
    for seg in bv.segments:
        if not execute_only or (execute_only and seg.executable):
            print("Scanning from " + str(hex(seg.start)) + " to " + str(hex(seg.end)))
            results.append(scan(bv, sign, mask, seg.start, seg.end))
    print("Complete!")


def scan(bv, sign, mask, start, end):
    results = []
    buffer = bv.read(start, end-start)
    for i in range(0, len(buffer)-len(mask)):
        match = True
        for j in range(0, len(mask)):
            if mask[j] and buffer[i+j] != sign[j]:
                match = False
                break;
        if match:
            results.append(start+i)
            print("Match found: " + str(hex(results[-1])))
    
    return results


def aob_input(bv):
    aob_f = bn.interaction.TextLineField("Signature")
    segments_f = bn.interaction.ChoiceField("Segment Protections", ["All", "Only Executable"])
    if bn.interaction.get_form_input(["AoB Scanner", None, aob_f, segments_f], "AoB Scanner"):
        aob_scan(bv, aob_f.result, segments_f == "Only Executable") # TODO: Debug this

#====================#
#   vTable Scanner   #
#====================#

# NOTE: this hits heavy on the CPU, good thing we only need to run it once ;)

def find_vtables(bv):
    print("Scanning for possible virtual tables...")
    vtables = []
    for seg in bv.segments:
        if not seg.executable and not seg.writable and seg.readable:
            vtables.append(scan_vtables_area(bv, seg.start, seg.end)) # scan readonly sections
    print("Done!")


def is_valid_child(bv, address):
    vfunc = struct.unpack('<I', bv.read(address, bv.arch.address_size))[0]  
    if len(bv.get_code_refs(address)) == 0 and bv.is_offset_executable(vfunc):
        return True
    return False


def scan_vtables_area(bv, start, end):
    buffer = bv.read(start, end-start)
    for i in range(0, len(buffer), bv.arch.address_size): # 4 or 8 depending on 32/64 bit
        crefs = bv.get_code_refs(start + i)
        if len(crefs) > 0: # has atleast one code reference, is constructor?
            # check if table ptr is executable
            vfunc = struct.unpack('<I', bv.read(start+i, bv.arch.address_size))[0]
            
            if not bv.is_offset_executable(vfunc):
                continue
            
            # check if xref is mov with reg dest
            match = False
            for rf in crefs:
                f = bv.get_functions_containing(rf.address)[0] # only need first one?
                ils = f.low_level_il
                for j in range(0, len(ils)):
                    if ils[j].address == rf.address:
                        # check if opcode is mov AND check if src is register AND check if dest is register
                        if (ils[j].operation == LowLevelILOperation.LLIL_STORE and
                            ils[j].src.operation == LowLevelILOperation.LLIL_CONST and
                            ils[j].dest.operation == LowLevelILOperation.LLIL_REG):
                            match = True
                            break
                        else:
                            break
            if match:
                print("Found vtable_" + str(hex(start+i))[2:] + "_0 at " + str(hex(start+i)))
                bv.set_comment_at(start+i, "vtable_" + str(hex(start+i))[2:] + "_0")
                
                # get children
                for j in range(start+i+bv.arch.address_size, end, bv.arch.address_size):
                    if is_valid_child(bv, j):
                        print("Found vtable_" + str(hex(j))[2:] + "_" + str(hex(j-start-i))[2:] + " at " + str(hex(j)))
                        bv.set_comment_at(j, "vtable_" + str(hex(j))[2:] + "_" + str(hex(j-start-i))[2:])
                    else:
                        break



# add to menu
bn.PluginCommand.register("AoB Scan","AoB_Scan", aob_input)
bn.PluginCommand.register("vTable Scan","vtable_scan", find_vtables)
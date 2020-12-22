import binaryninja as bn

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


bn.PluginCommand.register("AoB Scan","AoB_Scan", aob_input)
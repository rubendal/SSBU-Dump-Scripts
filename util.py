def adjustr2Output(output):
    if not '\r' in output:
        return output.replace('\n','\n\r')
    return output

def UseOpcode(val):
    return '_phx' in val or '_lib' in val or '_void' in val or 'section_end' in val or 'LOAD2' in val
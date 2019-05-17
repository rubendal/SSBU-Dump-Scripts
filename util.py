def adjustr2Output(output):
    if not '\r' in output:
        return output.replace('\n','\n\r')
    return output
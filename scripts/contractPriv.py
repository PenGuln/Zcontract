def RSP(val, indata) :
    res = (indata[0] - indata[1] + 3) % 3
    nval = val.copy()
    mn = min(nval[0], nval[1])
    if (res == 1): 
        nval[0] += mn
        nval[1] -= mn
    elif (res == 2): 
        nval[0] -= mn
        nval[1] += mn
    return nval, 0
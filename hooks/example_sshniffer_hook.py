def inbound_hook(inbound_data):
    print "Inbound hook working! Message Recieved! len:0x%lx"%len(inbound_data)
    return inbound_data

def outbound_hook(outbound_data):
    print "Outbound hook working! Message Recieved! len:0x%lx"%len(outbound_data)
    return outbound_data


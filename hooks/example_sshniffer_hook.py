def inbound_hook(inbound_data,userdata):
    print("Inbound hook working! Message Recieved! len:0x%lx"%len(inbound_data))
    try:
        userdata[inbound_data] = inbound_data
    except:
        pass
    return inbound_data

def outbound_hook(outbound_data,userdata):
    print("Outbound hook working! Message Recieved! len:0x%lx"%len(outbound_data))
    print(userdata)
    return outbound_data


def inbound_hook(inbound_data,userdata=""):
    import gzip
    import tempfile
    import os
    if "Content-Encoding: gzip" in inbound_data or "content-encoding: gzip" in inbound_data:
        data_loc = inbound_data.find("\r\n\r\n")
        if data_loc > -1:
            data = inbound_data[data_loc+4:]
            try:
                f,fname = tempfile.mkstemp()
                f.write(data)
                f.close()
                with gzip.open(fname,"rb") as gz:
                    decoded = gz.read()
                os.remove(fname)
                
                inbound_data = inbound_data[:data_loc+4] + decoded
        
                inbound_data = inbound_data.replace("Content-Encoding: gzip","Content-Encoding: text")
                inbound_data = inbound_data.replace("content-encoding: gzip","content-encoding: text")
            except:
                pass


    return inbound_data
     
        
def outbound_hook(outbound_data,userdata=""):
    return outbound_data


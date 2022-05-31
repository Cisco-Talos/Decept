#!/usr/bin/env python
import re
import os
import sys
import md5
import struct
# 
#
def main(dumpraw_dir,delim="",indexes=""):
    dir_list = []
    file_list = []
    hash_dict = {}
    request_dict = {}

    if delim:
        delim_buf = ""
        if "\\x" in delim: 
            delim_buf = ''.join([chr(int(x,16)) for x in filter(None,delim.split("\\x"))])
        else:
            try:
                delim_buf = ''.join([chr(int(x,16)) for x in filter(None,delim.split("x"))])
            except:
                delim_buf = delim

    # directory structure of a --dumpraw:
    # basedir
    #### <dateGenerated>
    #########session-X-Y-[inbound|outbound]
    # for x => session num, y => message num in session
    outdir = os.path.join(dumpraw_dir,"minimized")
    attempt_counter = 0

    while True:
        try:
            os.mkdir(outdir) 
            print("[0.0] Minimized dir: %s"%outdir)
            break
        except:
            outdir = os.path.join(dumpraw_dir,"minimized_%d"%attempt_counter)
            attempt_counter += 1
            if attempt_counter >=20:
                print("Comon, get rid of some of those old minimized_* dirs. Exiting")
                sys.exit()
                
    for f in os.listdir(dumpraw_dir):
        dirpath = os.path.join(dumpraw_dir,f)
        if not os.path.isdir(dirpath):
            continue 
        if "minimized" in f:
            continue
        dir_list.append(dirpath) 
       
    total_file_counter = 0
    valid_file_regex = re.compile(r'^session-(\d+)-(\d+)-(in|out)bound$') 
    for d in dir_list:
        listing = os.listdir(d)
        for f in listing:
            result = re.match(valid_file_regex,f)

            if not result:
                continue

            inp_file = os.path.join(d,f)
            if os.path.isdir(inp_file):
                continue

            try:
                with open(inp_file,'rb') as f:
                    inp_buf = f.read()
                    md5hash = md5.new(inp_buf).digest() 
                    hash_dict[inp_file] = md5hash 
                    total_file_counter+=1
            except Exception as e:
                print(e)
                continue

    print("[1.1] %d entries found in dump_directory" % total_file_counter)
    print("[2.2] Added %d unique entries to hash_dict" % len(hash_dict))
    
    if delim:
        print("[3.3] Sorting the entries based on delimeter: %s"%repr(delim_buf))
    elif indexes: 
        print("[3.3] Sorting the entries bytes in file: %s"%str(indexes))
    
    request_count = 0
    for filename in hash_dict:
        with open(filename,"rb") as f:
            inp_buf = f.read()

        if not len(inp_buf):
            continue

        #if delim:
        #    while  
        
        if indexes:
            key = ""
            for num in indexes:
                try: 
                    key+=inp_buf[num] 
                except:
                    print("Small file? %s" %(filename))
            try:
                _ = request_dict[key]    
            except:
                request_dict[key] = inp_buf
                request_count+=1
                # copy over to min dir.
                file_id = "id_0x" + ''.join(["%02x"%ord(y) for y in key])
                min_file = os.path.join(outdir,file_id)
                with open(min_file,"wb") as f:
                    f.write(inp_buf)
                
    template = ""
    print ("[4.4] Reduced down to %d unique requests"%request_count)
    try:
        template_loc = os.path.join(os.path.dirname(os.path.abspath(__file__)),"replayer_template.py")
        with open(template_loc,"rb") as f:
            template = f.read()
    except:
        print("[x.x] Could not find api_replayer.py template:%s..." % template_loc)
        sys.exit()    
    
    for i in range(0,100):
        fname = 'api_replayer_%d.py'%i
        if os.path.isfile(fname):
            continue
        with open(fname,"wb") as f: 
            work_dir = outdir + "_workdir"
            template = template.replace("inp_dir = %s","inp_dir = \"%s\""%os.path.abspath(outdir))
            template = template.replace("work_dir = %s","work_dir = \"%s\""%os.path.abspath(work_dir))
            f.write(template)
            break
        print("[>.>]; Why are there 100 api_replayers here....?")
        sys.exit()
    print("[^_^] There should hopfully be a %s script now, cheers." %fname)
                

def usage():
    print("<(^_^)> Decept's API script generator.\
           \n**********************************\
           \nPass it a decept --dumpraw directory and the delimeter used for the api reqs.\
           \nHopefully you'll get a cool script to play with the api in return.\
           \n(For nonprintable delims, use \\x0a\\x0d... format)\
           \n\n%s <dumpraw_dir> '<api_delim>'\
           \n\nAlternatively, use --index to sort by the set of bytes inside the index\
           \nfiles located at the i'th indexes (for i in numberRange <numRange>) \
           \n\n%s <dumpraw_dir> --index <numRange> (e.g. 1-4 or 1,3,9-15)\n"%(sys.argv[0],sys.argv[0]) )
    sys.exit()


# Takes a string of numbers, seperated via commas
# or by hyphens, and generates an appropriate list of
# numbers from it.
# e.g. str("1,2,3-6")  => list([1,2,xrange(3,7)])
#
# If flattenList=True, will return a list of distinct elements
#
# If given an invalid number string, returns None
def validateNumberRange(inputStr, flattenList=False):
    retList = []
    tmpList = filter(None,inputStr.split(','))

    # Print msg if invalid chars/typo detected
    for num in tmpList:
        try:
            retList.append(int(num))
        except ValueError:
            if '-' in num:
                intRange = num.split('-')
                # Invalid x-y-z
                if len(intRange) > 2:
                    print("Invalid range given")
                    return None
                try:
                    if not flattenList:
                        # Append iterator with bounds = intRange
                        retList.append(xrange(int(intRange[0]),int(intRange[1])+1))
                    else:
                        # Append individual elements
                        retList.extend(range(int(intRange[0]),int(intRange[1])+1))
                except TypeError:
                    print("Invalid range given")
                    return None
            else:
                try:
                    retList.append(float(num))
                except:
                    print("Invalid number given")
                    return None
    # All elements in the range are valid integers or integer ranges
    if flattenList:
        # If list is flattened, every element is an integer
        retList = sorted(list(set(retList)))
    return retList



if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
    
    dumpdir = sys.argv[1]    
    delim = ""
    index_list = ""

    try:
        tmp = sys.argv.index("--index")
        index_list = validateNumberRange(sys.argv[tmp+1],flattenList=True)
    except ValueError:
        delim = sys.argv[2]
    except IndexError:
        print("No index range for --index was found [;_;]")
        sys.exit()

    main(dumpdir,delim,index_list)

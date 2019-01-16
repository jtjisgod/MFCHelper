import pefile
import struct

p32 = lambda x: struct.pack("<L", x)
u32 = lambda x: struct.unpack("<L", x)

def main() :

    path = '/Users/jangtaejin/Desktop/CORNPlayerW.x86/CORNPlayerW.x86.exe'

    print("Loading ... [%s]"%(path))
    f = open(path, 'rb')
    binary = f.read()
    f.close()

    print("Checking ... [%s]"%(path))
    if b'CDialogEx' not in binary :
        print("This binary is not MFC")
        return
    print("Sucess! This is MFC")

    print("Parsing ... [%s]"%(path))
    pe = pefile.PE(path)

    rdata = b''
    start = 0
    end = 0

    for section in pe.sections :
        # print(section.Name.decode())
        if section.Name.decode().strip('\x00') == ".rdata" :
            rdata = section.get_data()
    
    print("Rdata : 0x%.8x ~ 0x%.8x"%(start, end))
        
    id = p32(1)
    id = id + id

    print("ID : ", id)
    cnt = 0

    offsets = []
    offset = 0
    while True :
        offset = rdata.find(id, offset+1)
        if offset == -1 :
            break
        offsets.append(offset)
    
    addrs = []
    for base in offsets :
        offset = 8
        nsig = u32(rdata[base+offset:base+offset+4])
        if nsig[0] > 1000 :
            continue
        offset += 4
        address = u32(rdata[base+offset:base+offset+4])[0]
        if(address > 0x400000) :
            addrs.append(address)
    
    for addr in addrs :
        print(hex(addr)) 
    

    # pe.parse_data_directories()
    # for entry in pe.DIRECTORY_ENTRY_IMPORT:
    #     print(entry.dll.decode())

if __name__ == "__main__" :
    main()
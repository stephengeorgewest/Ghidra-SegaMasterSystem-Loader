package smsloader;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class RomHeader {

    private byte[] bytes;
    
    public RomHeader(byte[] bytes) throws IllegalArgumentException {
        if(bytes.length != 5){
            throw new IllegalArgumentException("bytes wrong size");
        }
        this.bytes = Arrays.copyOf(bytes, 5);
    }

    public int checksum() {
/*
        byte[] checksumbytes = Arrays.copyOfRange(this.bytes,0,1);
        ByteBuffer bc = ByteBuffer.wrap(checksumbytes);
        return bc.getInt();
*/
        return bytes[0]&0xff | ((bytes[1]&0xff)<< 8);
    }
    
    public int productCode(){
/*
        byte[] productcodebytes = Arrays.copyOfRange(this.bytes,2,3);
        ByteBuffer bp = ByteBuffer.wrap(productcodebytes);
        return bp.getInt();*/
        return bytes[2]&0xff | ((bytes[3]<< 8)&0xff00);
    }

    public int version(){
        return bytes[4]&0xff;
    }

    public String toString(){
        return String.format(
            "ROM Header\r\nChecksum 0x%h\r\nProduct Code 0x%h\r\nVersion 0x%h",
            this.checksum(),
            this.productCode(),
            this.version()
        );
    }
}

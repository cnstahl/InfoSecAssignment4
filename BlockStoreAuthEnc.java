// This class provides a BlockStore that guarantees confidentiality and
// integrity of all the data it holds.  The constructor takes a BlockStore
// (which doesn't guarantee confidentiality and integrity).
//
// YOU WILL MODIFY THIS FILE.  The code we have provided here does not
// actually do anything to provide confidentiality and integrity.  You have
// to fix that.

import java.util.Arrays;

public class BlockStoreAuthEnc implements BlockStore {
    private BlockStore    dev;
    private PRGen         prg;
    public static final int KEY_BYTES = PRF.KEY_SIZE_BYTES;
    public static final int HASH_BYTES = PRF.OUTPUT_SIZE_BYTES;
    
    private boolean blockIsEmpty(int blockNum) throws DataIntegrityException{
        byte[] value = new byte[dev.blockSize()];
        byte[] empty = new byte[dev.blockSize()];
        dev.readBlock(blockNum, value, 0, 0, dev.blockSize());
        return Arrays.equals(value, empty);
    }
    
    private boolean checkIntegrity(int blockNum) throws DataIntegrityException{
        byte[] key = new byte[KEY_BYTES]; //FIXED KEY 0
        byte[] value = new byte[blockSize()];
        byte[] hashLeft = new byte[HASH_BYTES];
        byte[] hashRight = new byte[HASH_BYTES];
        
        byte[] oldHash = new byte[HASH_BYTES];
        byte[] calculatedHash = new byte[HASH_BYTES];

        //CHECK SUPERBLOCK
        if(blockNum==-1){
            dev.readBlock(0, oldHash, 0, blockSize(), HASH_BYTES);
            dev.readSuperBlock(calculatedHash, 0, superBlockSize(), HASH_BYTES);
            if (Arrays.equals(oldHash,calculatedHash))
                return true;
            else
                return false;
        }
            
        //Adjust index for tree traversal
        blockNum=blockNum+1;
        
        //If block is empty, integrity depends on the node's parent
        if (blockIsEmpty(blockNum-1))
            return checkIntegrity((blockNum/2)-1); 
        
        dev.readBlock(blockNum-1, value, 0, 0, blockSize());
        dev.readBlock(blockNum-1, oldHash, 0, blockSize(), HASH_BYTES);
        dev.readBlock(2*blockNum-1, hashLeft, 0, blockSize(), HASH_BYTES);
        dev.readBlock(2*blockNum, hashRight, 0, blockSize(), HASH_BYTES);
        
        PRF prf = new PRF(key);
        prf.update(hashLeft);
        prf.update(hashRight);
        calculatedHash=prf.eval(value);
        
        if (Arrays.equals(oldHash,calculatedHash))
            return checkIntegrity(blockNum/2-1);
        else{
            System.out.println(blockNum-1);
            return false;
        }
    }
    
    private void updateHash(int blockNum) throws DataIntegrityException{
        byte[] key = new byte[KEY_BYTES];
        byte[] value = new byte[blockSize()];
        byte[] hashLeft = new byte[HASH_BYTES];
        byte[] hashRight = new byte[HASH_BYTES];
        
        byte[] hash = new byte[HASH_BYTES];

        //CHECK SUPERBLOCK
        if(blockNum==-1){
            dev.readBlock(0, hash, 0, blockSize(), HASH_BYTES);
            dev.writeSuperBlock(hash, 0, superBlockSize(), HASH_BYTES);
            return;
        }
            
        //Adjust index for tree traversal
        blockNum=blockNum+1;
        
        dev.readBlock(blockNum-1, value, 0, 0, blockSize());
        dev.readBlock(2*blockNum-1, hashLeft, 0, blockSize(), HASH_BYTES);
        dev.readBlock(2*blockNum, hashRight, 0, blockSize(), HASH_BYTES);
        
        PRF prf = new PRF(key);
        prf.update(hashLeft);
        prf.update(hashRight);
        hash=prf.eval(value);
        
        dev.writeBlock(blockNum-1, hash, 0, blockSize(), HASH_BYTES);
        updateHash(blockNum/2-1);
    }
    
    public BlockStoreAuthEnc(BlockStore underStore, PRGen thePrg) 
    throws DataIntegrityException {
        dev = underStore;
        prg = thePrg; 
    }

    public void format() throws DataIntegrityException { 
        dev.format();
    }

    public int blockSize() {
        return dev.blockSize()-HASH_BYTES;
    }

    public int superBlockSize() {
        return dev.superBlockSize()-HASH_BYTES;
    }

    public void readSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
        int nbytes) throws DataIntegrityException {
        if(blockOffset+nbytes > superBlockSize()){
            throw new ArrayIndexOutOfBoundsException();
        }
        dev.readSuperBlock(buf, bufOffset, blockOffset, nbytes);
    }

    public void writeSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
        int nbytes) throws DataIntegrityException {        
        if(blockOffset+nbytes > superBlockSize()){
            throw new ArrayIndexOutOfBoundsException();
        }
        dev.writeSuperBlock(buf, bufOffset, blockOffset, nbytes);
    }

    public void readBlock(int blockNum, byte[] buf, int bufOffset, 
        int blockOffset, int nbytes) throws DataIntegrityException {
        if(!checkIntegrity(blockNum)){
            throw new DataIntegrityException();
        }
        if(blockOffset+nbytes > blockSize()){
            throw new ArrayIndexOutOfBoundsException();
        }
        
        dev.readBlock(blockNum, buf, bufOffset, blockOffset, nbytes);
    }

    public void writeBlock(int blockNum, byte[] buf, int bufOffset, 
        int blockOffset, int nbytes) throws DataIntegrityException {
        if(!checkIntegrity(blockNum)){
            throw new DataIntegrityException();
        }
        if(blockOffset+nbytes > blockSize()){
            throw new ArrayIndexOutOfBoundsException();
        }   
        
        dev.writeBlock(blockNum, buf, bufOffset, blockOffset, nbytes);
        updateHash(blockNum);
    }
}

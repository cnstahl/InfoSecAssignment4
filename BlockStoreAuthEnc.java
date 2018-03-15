//Group Net IDs: cnstahl mihalisa ls24
// This class provides a BlockStore that guarantees confidentiality and
// integrity of all the data it holds.  The constructor takes a BlockStore
// (which doesn't guarantee confidentiality and integrity).

import java.util.Arrays;

public class BlockStoreAuthEnc implements BlockStore {
    private BlockStore    dev;
    private PRGen         prg;
    private static final int KEY_BYTES = PRF.KEY_SIZE_BYTES;
    private static final int HASH_BYTES = PRF.OUTPUT_SIZE_BYTES;
    private byte[] key;

    // This function checks if the blockNum is empty adn retruns TRUE if it is
    // or false otherwise.
    private boolean blockIsEmpty(int blockNum) throws DataIntegrityException{
        byte[] value = new byte[dev.blockSize()];
        byte[] empty = new byte[dev.blockSize()];
        dev.readBlock(blockNum, value, 0, 0, dev.blockSize());
        return Arrays.equals(value, empty);
    }
    
    // CheckIntegrity implements a modified Merkle Tree (source: Wikipedia.com)
    // If the integrity of the storage is maintained it returns true and
    // returns false if it has been tampered.
    private boolean checkIntegrity(int blockNum) throws DataIntegrityException{
        byte[] key = new byte[KEY_BYTES]; //FIXED KEY 0
        byte[] value = new byte[blockSize()];
        byte[] hashLeft = new byte[HASH_BYTES];
        byte[] hashRight = new byte[HASH_BYTES];
        
        byte[] oldHash = new byte[HASH_BYTES];
        byte[] calculatedHash = new byte[HASH_BYTES];

        //CHECK SUPERBLOCK's HASH is SAME as the FIRST HASH and return true if it is
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
        
        //READ VALUE OF NODE, HASH OF CHILDREN AND HASH OF NODE
        dev.readBlock(blockNum-1, value, 0, 0, blockSize());
        dev.readBlock(blockNum-1, oldHash, 0, blockSize(), HASH_BYTES);
        dev.readBlock(2*blockNum-1, hashLeft, 0, blockSize(), HASH_BYTES);
        dev.readBlock(2*blockNum, hashRight, 0, blockSize(), HASH_BYTES);
        
        //CALCULATE THE HASH AGAIN
        PRF prf = new PRF(key);
        prf.update(hashLeft);
        prf.update(hashRight);
        calculatedHash=prf.eval(value);
        
        //COMPARE HASHES. IF DIFFERENT THEN RETURN FALSE, OTHERWISE RETURN
        //INTEGRITY OF PARENT RECURSIVELY (until reaching superblock)
        if (Arrays.equals(oldHash,calculatedHash))
            return checkIntegrity(blockNum/2-1);
        else{
            //System.out.println("Integrity Error in blockNum" + blockNum-1);
            return false;
        }
    }
    
    // Updates the "Merkle Tree" after writing with new hashes
    private void updateHash(int blockNum) throws DataIntegrityException{
        byte[] key = new byte[KEY_BYTES];
        byte[] value = new byte[blockSize()];
        byte[] hashLeft = new byte[HASH_BYTES];
        byte[] hashRight = new byte[HASH_BYTES];
        
        byte[] hash = new byte[HASH_BYTES];

        //Write top hash to superblock and return.
        if(blockNum==-1){
            dev.readBlock(0, hash, 0, blockSize(), HASH_BYTES);
            dev.writeSuperBlock(hash, 0, superBlockSize(), HASH_BYTES);
            return;
        }
            
        //Adjust index for tree traversal
        blockNum=blockNum+1;
        
        //Get value of node and hashes of children
        dev.readBlock(blockNum-1, value, 0, 0, blockSize());
        dev.readBlock(2*blockNum-1, hashLeft, 0, blockSize(), HASH_BYTES);
        dev.readBlock(2*blockNum, hashRight, 0, blockSize(), HASH_BYTES);
        
        //Hash all of these values
        PRF prf = new PRF(key);
        prf.update(hashLeft);
        prf.update(hashRight);
        hash=prf.eval(value);
        
        //Write it to node and recursively call to parent node until reaching the
        //SuperBlock (blockNum=-1).
        dev.writeBlock(blockNum-1, hash, 0, blockSize(), HASH_BYTES);
        updateHash(blockNum/2-1);
    }
    
    public BlockStoreAuthEnc(BlockStore underStore, PRGen thePrg) 
    throws DataIntegrityException {
        dev = underStore;
        prg = thePrg; 
        key = new byte[32];
        byte[] empty = new byte[KEY_BYTES];
        
        // Read SuperBlock for key. If key does not exist, create new one and
        // store it in the superBlock.
        dev.readSuperBlock(key, 0, superBlockSize()+HASH_BYTES, KEY_BYTES);
        if(Arrays.equals(key, empty)){
           for(int i = 0; i < KEY_BYTES; i++) {
               key[i] = (byte) prg.next(8);
           }
           dev.writeSuperBlock(key, 0, superBlockSize()+HASH_BYTES, KEY_BYTES);
        }
    }

    public void format() throws DataIntegrityException { 
        dev.format();
    }

    // Return free size of Block by substracting the HASH_BYTES
    public int blockSize() {
        return dev.blockSize()-HASH_BYTES;
    }

    // Return free size of SuperBlock by substracting the HASH_BYTES and KEY_BYTES
    public int superBlockSize() {
        return dev.superBlockSize()-HASH_BYTES-KEY_BYTES;
    }

    // Read SuperBlock by checking range of reading operation and calling
    //parent function (as it is already secure).
    public void readSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
        int nbytes) throws DataIntegrityException {
        if(blockOffset+nbytes > superBlockSize()){
            throw new ArrayIndexOutOfBoundsException();
        }
        dev.readSuperBlock(buf, bufOffset, blockOffset, nbytes);
    }

    // Write SuperBlock by checking range of writing operation and calling
    //parent function (as it is already secure).
    public void writeSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
        int nbytes) throws DataIntegrityException {        
        if(blockOffset+nbytes > superBlockSize()){
            throw new ArrayIndexOutOfBoundsException();
        }
        dev.writeSuperBlock(buf, bufOffset, blockOffset, nbytes);
    }

    // Read Block checking bounds and integrity, and performing decryption.
    public void readBlock(int blockNum, byte[] buf, int bufOffset, 
        int blockOffset, int nbytes) throws DataIntegrityException {
        //Integrity Check
        if(!checkIntegrity(blockNum)){
            throw new DataIntegrityException();
        }
        //Bound check
        if(blockOffset+nbytes > blockSize()){
            throw new ArrayIndexOutOfBoundsException();
        }
        
        byte[] encBuf = new byte[blockSize()];
        byte[] decBuf = new byte[blockSize()];

        //Read Block
        dev.readBlock(blockNum, encBuf, 0, 0, blockSize());
        // Cipher the block with nonce equal to blockNum
        byte[] nonce = new byte[8];
        LongUtils.longToBytes((long) blockNum, nonce, 0);
        StreamCipher cipher = new StreamCipher(key, nonce, 0);
        cipher.cryptBytes(encBuf, 0, decBuf, 0, blockSize());
        // Copy the required decrypted part onto the output array (buf)
        System.arraycopy(decBuf, blockOffset, buf, bufOffset, nbytes);
    }

    // Write to Block checking bounds and integrity, and performing encryption.
    public void writeBlock(int blockNum, byte[] buf, int bufOffset, 
        int blockOffset, int nbytes) throws DataIntegrityException {
        //Integrity Check
        if(!checkIntegrity(blockNum)){
            throw new DataIntegrityException();
        }
        //Bound Check
        if(blockOffset+nbytes > blockSize()){
            throw new ArrayIndexOutOfBoundsException();
        }
        
        byte[] encBuf = new byte[blockSize()];
        byte[] zerBuf = new byte[blockSize()];

        //Create StreamCipher with nonce equal to blockNum
        byte[] nonce = new byte[8];
        LongUtils.longToBytes((long) blockNum, nonce, 0);
        StreamCipher cipher = new StreamCipher(key, nonce, 0);
        //Copy buf from buffOffset to buffOffset+nbytes-1 onto zerBuf and encrypt
        System.arraycopy(buf, bufOffset, zerBuf, blockOffset, nbytes);
        cipher.cryptBytes(zerBuf, 0, encBuf, 0, blockSize());
        //Write the required part onto the block
        dev.writeBlock(blockNum, encBuf, blockOffset, blockOffset, nbytes);
        //Update Integrity
        updateHash(blockNum);
    }
}
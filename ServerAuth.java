
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;

import java.io.IOException;


public class ServerAuth {
  private static final int HASH_BYTES = PRF.OUTPUT_SIZE_BYTES;
  private static final int KEY_BYTES = PRF.KEY_SIZE_BYTES;
  private ArrayStore            as;
  private BlockStoreMultiplexor multiplexor;

  private BlockStore            lastBlockStoreAllocated;
  // CREATE, MODIFY, OR DELETE FIELDS AS NEEDED

  public ServerAuth(BlockStore myBlockStore, BlockStoreMultiplexor bsm) {
    // bsm is a BlockStoreMultiplexor we can use
    // myBlockStore is a BlockStore that was created using bsm, which
    // is available for use in keeping track of authentication info
    as = new ArrayStore(myBlockStore);
    multiplexor = bsm;
  }

  //Returns the index for username "user". Returns -1 if user does not exist.
  private int userIndex(byte[] user) throws DataIntegrityException{
      int numberAccounts = multiplexor.numSubStores()-1;
      int sizeUser = (user.length>100) ? 100 : user.length;
      
      byte[] reader = new byte[100];
      byte[] comparer = new byte[100];
      System.arraycopy(user,0,comparer,0,sizeUser);
      for (int i=0; i<numberAccounts; i++){
         as.read(reader, 0, 100*i, 100);
         if(Arrays.equals(reader,comparer))
             return i+1;
      }
      return -1;
  }
  
  public BlockStore createUser(String username, String password) 
  throws DataIntegrityException {
    // If there is already a user with the same name, return null.
    // Otherwise, create an account for the new user, and return a
    // BlockStore that the new user can use
    //
    // The code we are providing here is insecure.  It just sets up a new
    // BlockStore in all cases, without checking if the name is already taken,
    // and without storing any information that might be needed for 
    // authentication later.
    byte[] user = username.getBytes();
    byte[] pass = password.getBytes();
    if (userIndex(user)!=-1)
        return null;
    //Create New SubStore
    int numberAccounts = multiplexor.numSubStores()-1;
    BlockStore userBlock = multiplexor.newSubStore();
    userBlock.format();
    
    //Store Username in ArrayStore (which is safe because it was created with
    //the bsm which is implemented by our secure BlockStoreAuthEnc
    int sizeUser = (user.length>100) ? 100 : user.length;
    as.write(user, 0, 100*numberAccounts, sizeUser);
    
    //Hash key with username
    byte[] key = new byte[KEY_BYTES];
    PRF prf = new PRF(key);
    byte[] hash = prf.eval(user);
    //Store in "virtual" SuperBlock space allocated in Multiplexor for each SubStore
    userBlock.writeSuperBlock(hash,0,0,HASH_BYTES);
    return userBlock;  
  }

  public BlockStore auth(String username, String password) 
  throws DataIntegrityException {    
    // If there is not already a user with the name <username>, or if there
    // is such a user but not with the given <password>, then return null.
    // Otherwise return the BlockStore that holds the given user's data.
    //
    // The code we are providing here is insecure. Its behavior doesn't 
    // depend on <username> or <password>.  And if it returns a BlockStore,
    // it isn't necessarily the one associated with the given username.
    byte[] user = username.getBytes();
    byte[] pass = password.getBytes();
    int index = userIndex(user);
    if (index==-1)
        return null;
    BlockStore userBlock = multiplexor.getSubStore(index);
    
    byte[] storedHash = new byte[HASH_BYTES];
    userBlock.readSuperBlock(storedHash,0,0,HASH_BYTES);
    
    byte[] key = new byte[KEY_BYTES];
    PRF prf = new PRF(key);
    byte[] calculatedHash = prf.eval(user);
    
    if(!Arrays.equals(calculatedHash,storedHash))
           return null;
    
    return userBlock;
    }
}

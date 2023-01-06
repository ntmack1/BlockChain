/* BlockChain.java

Version 1.0 2022-11-1:

Author: Nathan Mack, referencing Professor Elliott's bc.java and BlockJ.java

Professor Elliott's references, which I indirectly used via his code:

https://mkyong.com/java/how-to-parse-json-with-gson/
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html

One version of the JSON jar file here:
https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.2/

Program instructions:

You will need to download gson-2.8.2.jar into your classpath / compiling directory.

To compile and run on Windows:

javac -cp "gson-2.8.2.jar" Blockchain.java
java -cp ".;gson-2.8.2.jar" Blockchain

See Mac/Unix tips from the website if you are on the Mac. For example you
may need to replace ";" with ":"

javac -cp \"gson-2.8.2.jar\" *.java"

java -cp \".:gson-2.8.2.jar\ Blockchain 0

Ports used:

Port 4710+process number receives public keys (4710, 4711, 4712)

Port 4820+process number receives unverified blocks (4820, 4821, 4822)

Port 4930+process number receives updated blockchains (4930, 4931, 4932) 

-----------------------------------------------------------------------------------------------------*/
import java.io.*;
import java.util.*;
import java.util.concurrent.PriorityBlockingQueue;
import com.google.gson.Gson; //Converts objects to JSON format, references a JAR file 
import com.google.gson.GsonBuilder;
import java.net.*; // Needed for making threads
//Java.security needed for public and private keys and for signing and hashing
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class Blockchain {
	static ArrayList<BlockRecord> ledger = new ArrayList<>(); //This is the Blockchain ledger which stores all transactions
	static int numProcesses = 3; //For this assignment, there are three processes (0,1,2)
	static int PID; //Variable stores process ID which is obtained from the command line
	static boolean waitForProcess2 = true; //This variable remains true until process 2 has been started up and changes this to false
	static KeyPair keyPair; //The public/private key pair for this particular process
	static HashMap<Integer, PublicKey> publicKeyDict = new HashMap<>(); //holds the public keys of all participating processes
	
	public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>() //comparator needed for priority queue
	{
		@Override
		public int compare(BlockRecord b1, BlockRecord b2)
		{
			//System.out.println("In comparator");
			String s1 = b1.getTimeStamp();
			String s2 = b2.getTimeStamp();
			if (s1 == s2) {return 0;}
			if (s1 == null) {return -1;}
			if (s2 == null) {return 1;}
			return s1.compareTo(s2);
		}
	};
	
	//priority queue is thread safe and holds all unverified blocks 
	static PriorityBlockingQueue<BlockRecord> unverifiedQueue = new PriorityBlockingQueue<>(100, BlockTSComparator);
	
	public static void main (String[] args) {
		//Get PID from command line argument
		PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]);
		
		System.out.println("Nathan Mack's Block Coordination Framework. Use Control-C to stop the process.\n");
		System.out.println("Using processID " + PID + "\n");

		//Create public and private key pair for this process
		try {
			keyPair = generateKeyPair(20);
		} catch (Exception e1) {e1.printStackTrace();}

		//Create the Genesis Block, append to ledger (same block for all processes)
		BlockRecord Block0 = createBlock0();
		ledger.add(Block0);

		//readInData() returns a linked list of unverified blocks created from data read in from a file
		System.out.println("Processing file data into unverified blocks");
		LinkedList<BlockRecord> unverifiedList = readInData();

		//Start new thread to receive public keys at port 4710+process 
		PublicKeyReceiver pkr = new PublicKeyReceiver();
		Thread thread1 = new Thread(pkr);
		thread1.start();

		//Start new thread to receive unverified blocks at port 4820+process
		UnverifiedBlockReceiver ubr = new UnverifiedBlockReceiver();
		Thread thread2 = new Thread(ubr);
		thread2.start();

		//Start new thread to receive updated blockchains at port 4930+process
		UpdatedBlockChainReceiver ucr = new UpdatedBlockChainReceiver();
		Thread thread3 = new Thread(ucr);
		thread3.start();

		//Sleep for 2 seconds to allow time for threads to set up
		try {Thread.sleep(2000);} catch (InterruptedException e) {e.printStackTrace();} 
		
		//Process 2 starts all other processes. All processes wait in a loop until Process 2 sends signal.
		if (PID != 2) {
			while(waitForProcess2) {
				try {Thread.sleep(1000);} catch (InterruptedException e) {e.printStackTrace();} 
			}
		}
		multicastKeys(keyPair.getPublic()); //Multicast public key to all members
		try {Thread.sleep(1000);} catch (InterruptedException e) {e.printStackTrace();}
				
		multicastUnverifiedBlocks(unverifiedList); //Multicast unverified blocks to all members
		try {Thread.sleep(2000);} catch (InterruptedException e) {e.printStackTrace();} 
		
		//begin to solve the puzzles and Multicast updated block chain to all members (once a block has been solved and appended to the chain)
		new Thread(new UnverifiedBlockConsumer(unverifiedQueue, ledger)).start(); // Start consuming the unverified blocks from queue
	}
	//Method that generates a public/private key pair for each process
	public static KeyPair generateKeyPair(long seed) throws Exception {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
		rng.setSeed(seed);
		keyGenerator.initialize(1024, rng);

		return (keyGenerator.generateKeyPair());
	}
	//Method to create and populate the Genesis Block (Block 0) in ledger
	public static BlockRecord createBlock0() {
		BlockRecord Block0 = new BlockRecord();
		//Fill Block With Dummy Data
		Block0.setBlockID("0");
		Block0.setTimeStamp("0");
		Block0.setCreatingProcessID("0");
		Block0.setVerificationProcessID("0");
		Block0.setPreviousHash("0");
		Block0.setRandomSeed("0");
		Block0.setWinningHash("05ege617d326f229901838c03617e3ac23b3ca1ae9212226137ddc2af876a24b");
		Block0.setUUID(UUID.fromString("46084a73-bc53-445a-999a-474c19b5e66d")); 
		Block0.setFname("A");
		Block0.setLname("B");
		Block0.setSSNum("0");
		Block0.setDOB("0");
		Block0.setDiag("0");
		Block0.setTreat("0");
		Block0.setRx("0");
		return Block0;
	}
	//Method to read in data from file into an unverified block
	public static LinkedList<BlockRecord> readInData() {
		//List where unverified blocks will be placed 
		LinkedList<BlockRecord> unverifiedList = new LinkedList<BlockRecord>();

		String fileName = "BlockInput" + PID + ".txt";
		//Read in File and process it line by line to fill the empty unverified block
		try {
			FileReader file = new FileReader(fileName);
			BufferedReader in = new BufferedReader(file);

			while (in.ready()) {
				String line = in.readLine();
				//pass line to a method which will process string and put appropriate values into the unverified block
				BlockRecord unverifiedBlock = parseLine(line);
				//Put block in a linked list that will be multicast later 
				unverifiedList.add(unverifiedBlock);
			}
			in.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return unverifiedList;
	}
	//method to parse a line from file and place it in an unverified block
	public static BlockRecord parseLine (String line) {
		//create a new empty block
		BlockRecord unverifiedBlock = new BlockRecord();

		//Enter metadata into block
		unverifiedBlock.setTimeStamp(Long.toString(System.currentTimeMillis()));
		unverifiedBlock.setCreatingProcessID(Integer.toString(Blockchain.PID));
		unverifiedBlock.setUUID(UUID.randomUUID());

		try {
			//Sign UUID:
			//Convert UUID to String in order to use method getBytes. Then input this 
			//byte array into signing method to sign the UUID
			String uuidString = unverifiedBlock.getUUID().toString();
			byte[] digitalSignature = signData(uuidString.getBytes(), keyPair.getPrivate());
			//encode signature as Base 64 and use that for signedUUID field
			unverifiedBlock.setSignedUUID(Base64.getEncoder().encodeToString(digitalSignature));

		} catch (Exception e) {e.printStackTrace();}

		//Begin Processing of data from file:
		//split the line by spaces
		String[] splitLine = line.split(" ");
		//enter all data from line into unverified block
		unverifiedBlock.setFname(splitLine[0]);
		unverifiedBlock.setLname(splitLine[1]);
		unverifiedBlock.setDOB(splitLine[2]); 
		unverifiedBlock.setSSNum(splitLine[3]);
		unverifiedBlock.setDiag(splitLine[4]); 
		unverifiedBlock.setTreat(splitLine[5]); 
		unverifiedBlock.setRx(splitLine[6]);

		return unverifiedBlock; 
	}
	//method to sign data using the processes' private key
	//other members can verify signature using public key of the corresponding process
	//public key is stored in a hashmap
	public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(key);
		signer.update(data);
		return (signer.sign());
	}
	//method sends the public key of the process to all other members
	public static void multicastKeys(PublicKey publicKey) {	
		Socket sock;
		ObjectOutputStream toServer;
		System.out.println("Beggining multicast of Public keys");
		try{
			for(int i=0; i< numProcesses; i++){
				sock = new Socket("localhost", 4710 + i); 
				//send hashmap to listening port using objectoutputstream 
				toServer = new ObjectOutputStream(sock.getOutputStream());
				//Line 0 is public key, line 1 is process ID associated with that public key
				toServer.writeObject(PID); 
				toServer.writeObject(publicKey); 
				toServer.flush();                                                     
				sock.close();
			}
		}catch (Exception x) {x.printStackTrace ();}
	}
	//method to send unverified blocks to all members, blocks were created from data read in from files
	public static void multicastUnverifiedBlocks(LinkedList<BlockRecord> unverifiedList) {
		Socket UVBsock; // Will be client connection to the Unverified Block Server for each other process.
		BlockRecord tempBlock;
		try{
			System.out.println("Beggining multicast of unverified blocks");
			Iterator<BlockRecord> iterator = unverifiedList.iterator();
			ObjectOutputStream toServerOOS = null; // Stream for sending Java objects
			//outer loop to connect with different members
			//inner loop to iterate through each block
			for(int i = 0; i < numProcesses; i++){//
				iterator = unverifiedList.iterator(); 
				while(iterator.hasNext()){
					//iterate through list of unverified blocks, send each block to all processes
					UVBsock = new Socket("localhost", 4820 + i); //port number described in assignment instructions
					//using objectoutputstream to send unverified blocks
					toServerOOS = new ObjectOutputStream(UVBsock.getOutputStream());
					tempBlock = iterator.next();
					//Marshall Block to JSON using GSON
					Gson gson = new Gson();
					String json = gson.toJson(tempBlock); 
					toServerOOS.writeObject(json); // Send the unverified block record object
					toServerOOS.flush();
					UVBsock.close();
				} 
			} 
		}catch (Exception x) {x.printStackTrace ();}
	}
}
//This class runs a thread which will listen for connections 
//for public keys and pass those connections to a worker thread
class PublicKeyReceiver implements Runnable {
	public void run() {
		int q_len = 6; //Number of requests held in queue while waiting for a connection
		int port = 4710 + Blockchain.PID; //Port number required by assignment
		Socket sock;

		try {
			//Creates a socket that will be used to connect with client
			ServerSocket servsock = new ServerSocket(port, q_len);

			//continually listens, creates a new thread for each new socket
			while (true) {
				sock = servsock.accept();
				PublicKeyWorker pkw = new PublicKeyWorker(sock);
				Thread thread = new Thread(pkw);
				thread.start();
			}
		} catch(IOException e){e.printStackTrace();}
	}
}
//Worker class for public keys
class PublicKeyWorker implements Runnable {
	Socket sock;
	//Constructor
	PublicKeyWorker(Socket sock) {this.sock = sock;}
	public void run() {
		//Thread 2 starts all other processes by changing the boolean value, thus stopping infinite while loop in main method
		Blockchain.waitForProcess2 = false;
		try {
			//read in each line, line 0 for PID, line 1 for pk
			ObjectInputStream fromServer = new ObjectInputStream(sock.getInputStream());
			int PID = (int) fromServer.readObject();
			PublicKey pk = (PublicKey) fromServer.readObject();
			//place PID/pk into "global" hashmap/dictionary to be referenced later
			Blockchain.publicKeyDict.put(PID, pk);
			sock.close();
		} catch (IOException | ClassNotFoundException e){e.printStackTrace();}
	}
}
//This class runs a thread which will listen for connections 
//for unverified blocks and pass those connections to a worker thread
class UnverifiedBlockReceiver implements Runnable {
	public void run() {
		int q_len = 6; //Number of requests held in queue while waiting for a connection
		int port = 4820 + Blockchain.PID; //Port number required by assignment
		Socket sock;
		try {
			//Creates a socket that will be used to connect with client
			ServerSocket servsock = new ServerSocket(port, q_len);

			//continually listens, creates a new thread for each new socket
			while (true) {
				sock = servsock.accept();
				UnverifiedBlockWorker ubw = new UnverifiedBlockWorker(sock);
				Thread thread = new Thread(ubw);
				thread.start();
			}
		} catch(IOException e){e.printStackTrace();}
	}
}
//Worker class for unverified blocks
class UnverifiedBlockWorker implements Runnable {
	Socket sock;
	//Constructor
	public UnverifiedBlockWorker(Socket sock) {this.sock = sock;}
	
	public void run() {
		try {
			//receive string object in JSON format and unmarshall 
			//into a BlockRecord object, using GSON, which is appended to priority queue
			ObjectInputStream fromServerOIS = new ObjectInputStream(sock.getInputStream());
			String json = (String)fromServerOIS.readObject();
			Gson gson = new Gson();
			BlockRecord block = gson.fromJson(json, BlockRecord.class);
			Blockchain.unverifiedQueue.put(block);
			sock.close();
		} catch (IOException | ClassNotFoundException e){e.printStackTrace();}
	}
}
//This class runs a thread which will listen for connections 
//for updated blockchains and pass those connections to a worker thread
class UpdatedBlockChainReceiver implements Runnable {
	public void run() {
		int q_len = 6; //Number of requests held in queue while waiting for a connection
		int port = 4930 + Blockchain.PID; //Port number required by assignment
		Socket sock;
		try {
			//Creates a socket that will be used to connect with client
			ServerSocket servsock = new ServerSocket(port, q_len);

			//continually listens, creates a new thread for each new socket
			while (true) {
				sock = servsock.accept();
				UpdatedBlockChainWorker ubcw = new UpdatedBlockChainWorker(sock);
				Thread thread = new Thread(ubcw);
				thread.start();
			}
		} catch(IOException e){e.printStackTrace();}
	}
}
//worker class for updating the blockchain
class UpdatedBlockChainWorker implements Runnable {
	Socket sock;

	//Constructor
	public UpdatedBlockChainWorker (Socket sock) {this.sock = sock;}
	
	public static boolean verifyLedger(BlockRecord[] ledger) {
		//check if verified ledger is larger than old ledger
		//only accepts larger ledgers
		if (ledger.length <= Blockchain.ledger.size())
			return false;
		return true;
	}
	//method to simplify the writing of ledger to JSON file
	public static void writeJSON() {
	    Gson gson = new GsonBuilder().setPrettyPrinting().create();
	    ArrayList<BlockRecord> localLedger = Blockchain.ledger;
	    String json = "";
	    //iterate and append blocks in ledger to GSON builder
	    for (int i = 0; i < localLedger.size(); i++) {
	    	json = json + gson.toJson(localLedger.get(i)); 
	    }
	    //write to file
	    try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
	        writer.write(json);;
	    } catch (IOException e) {e.printStackTrace();}
	}
	public void run() {
		try {
			//receive json and unmarshall into a ledger object which is verified before becoming new ledger
	        BufferedReader fromServerOIS = new BufferedReader(new InputStreamReader(sock.getInputStream()));
	        String json = (String)fromServerOIS.readLine();
			Gson gson = new Gson();
	        BlockRecord[] ledger = gson.fromJson(json, BlockRecord[].class);
			boolean test = verifyLedger(ledger);
			//update ledger if tests pass
			if (test) {
				ArrayList<BlockRecord> ledgerUpdate = new ArrayList<>();
				for (int i = 0; i < ledger.length; i++) {
					ledgerUpdate.add(ledger[i]);
				}
				Blockchain.ledger = ledgerUpdate;
			}
			//PID 0 is the only process that writes to file 
			if (Blockchain.PID == 0) {
				writeJSON();
			}
			sock.close();
		} catch (IOException e){e.printStackTrace();}

	}
}
//This method looks at the queue of unverified blocks
//Adds metadata, and creates a hash "puzzle" to create work
//All process race to complete their "puzzle" first
class UnverifiedBlockConsumer implements Runnable {
	//Create local copy of queue and arrayList
	PriorityBlockingQueue<BlockRecord> queue; 
	ArrayList<BlockRecord> ledger;

	//Constructor 
	UnverifiedBlockConsumer(PriorityBlockingQueue<BlockRecord> queue, ArrayList<BlockRecord> ledger ){
		this.queue = queue;
		this.ledger = ledger;
	}
	//this method verified the signature of blocks by using the public key of the supposed block creator
	//as long as the block creator doesn't lose their private key. If their is a bad actor, the verifySig 
	//will faile and refuse to update block
	public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);

		return (signer.verify(sig));
	}	
	//creates a seed of whatever size you want. This will be hashed along with block data and previous winning hash
	public static String randomSeed (int seedSize) {
		String alphaNumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < seedSize; i++) {
			//generate a random number between 0 and 61 to use as an index in alphaNumeric to get random string of above characters
			int index = (int) (62 * Math.random());
			sb.append(alphaNumeric.charAt(index));
		}
		return sb.toString();
	}
	//method to send new ledger to all listening processes
	public static void multicastNewLedger(ArrayList<BlockRecord> ledger) {
		Socket sock; //client connection
		int numProcesses = Blockchain.numProcesses;
		//loop through ArrayList and put those values into a basic array
		//easier to marshall using GSON
		BlockRecord[] ledgerArray = new BlockRecord[ledger.size()];
		PrintStream toServer;
		for (int i = 0; i < ledger.size(); i++) {
			ledgerArray[i] = ledger.get(i);
		}
		try{
			System.out.println("Beggining multicast of new ledger");
            for(int i = 0; i < numProcesses; i++){
				sock = new Socket("localhost", 4930 + i);
				toServer = new PrintStream(sock.getOutputStream());
				//Marshall ledger to JSON using GSON
				Gson gson = new Gson();
				String json = gson.toJson(ledgerArray); 
				toServer.println(json); 
				toServer.flush();
				sock.close();
			} 
		}catch (Exception x) {x.printStackTrace ();}

	}
	//This is were the proof of work is done
	public void run(){
		BlockRecord tempRec;

		System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
		try{
			while(true){ 
				tempRec = queue.take(); //Pop the first block from priority queue

				//loops to see if block already in ledger, if so, pop this block and start a new block
				ArrayList<BlockRecord> localLedger = Blockchain.ledger;
				BlockRecord previousBlock = localLedger.get(localLedger.size() -1);
				//check if block has already been solved, if so, pop a new block
				for (int i = 0; i < localLedger.size(); i++) {
					if(tempRec.getUUID().equals(localLedger.get(i).getUUID())) {
						tempRec = queue.take();
						break;
					}
				}
				
				//verify the block by looking at the signature field of unverified block
				String processID = tempRec.getCreatingProcessID();
				byte[] data = tempRec.getUUID().toString().getBytes();
				byte[] sig = Base64.getDecoder().decode(tempRec.getSignedUUID());
				PublicKey key = Blockchain.publicKeyDict.get(Integer.parseInt(processID)); 	
				//provide public key of the signing process
				//also include the UUID of the block and include the signedUUID 
				//Use these three things to verify signature
				boolean verified = verifySig(data, key, sig);

				//Checks if block is verified, if not, the block is skipped 
				if (!verified) {
					System.out.println("Block is not verified");
					continue;
				}

				//Add more metadata for the verified block before beginning the work puzzle
				int prevID = Integer.parseInt(previousBlock.getBlockID());
				int newID = prevID + 1; //increment ID by 1
				tempRec.setBlockID(Integer.toString(newID));
				tempRec.setVerificationProcessID(Integer.toString(Blockchain.PID));
				tempRec.setPreviousHash(previousBlock.getWinningHash());

				//Do work on block to solve puzzle:
				//First we will form a string of some of the block data 
				//including: BlockID, TimeStamp, Previous Hash, Fname, Lname, SSN,
				StringBuilder sb = new StringBuilder();
				sb.append(tempRec.getBlockID());
				sb.append(tempRec.getTimeStamp());
				sb.append(tempRec.getPreviousHash());
				sb.append(tempRec.getFname());
				sb.append(tempRec.getLname());
				sb.append(tempRec.getFname());
				sb.append(tempRec.getSSNum());
				String toHash = sb.toString();

				String SHA256String = "";
				String randomSeed = "";
				String winningHash = "";

				MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
				//loop through until a successful seed string is found
				boolean leaveLoop = false;
				int testNumber;
				do {
					StringBuffer sbuff = new StringBuffer();
					//Create a random seed
					randomSeed = randomSeed(6);
					//Concatenate block data with random seed
					SHA256String = toHash + randomSeed;
					ourMD.update (SHA256String.getBytes());
					byte[] byteData = ourMD.digest();
					//convert byte array into hexadecimal using Professor Elliott's code snippet:
					for (int i = 0; i < byteData.length; i++) {
						sbuff.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
					}

					winningHash = sbuff.toString();
					//get first 4 hex digits, equivalent to first 16 bits, convert to base 10 for calculation
					testNumber = Integer.parseInt(winningHash.substring(0, 4), 16);

					//check if block has already been solved. If so, continue loop with the next block from queue
					ArrayList<BlockRecord> localLedger2 = Blockchain.ledger;
					//check if block has already been solved, if so, end this round of looping
					for (int i = 0; i < localLedger2.size(); i++) {
						if(tempRec.getUUID().equals(localLedger2.get(i).getUUID())) {
							leaveLoop = true;
						}
					}

				} while (testNumber > 1000 || leaveLoop); //test condition

				//start next iteration of loop
				if(leaveLoop) {
					continue;
				}
				System.out.println("Hash Successful, winning hash is " + testNumber);

				//Append metadata to block
				tempRec.setWinningHash(winningHash); 
				tempRec.setRandomSeed(randomSeed);

				//Add block to local version of ledger
				ledger.add(tempRec);

				//Multicast the new ledger to all parties 
				multicastNewLedger(ledger);

				Thread.sleep(1000); 
			}
		}catch (Exception e) {System.out.println(e);}
	}
}
//This class creates a block object, referencing Professor Elliott's BlockJ.java code
class BlockRecord {
	//Block metadata
	String BlockID;
	String TimeStamp;
	String CreatingProcessID;
	String VerificationProcessID;
	String PreviousHash; 
	UUID uuid; 
	String signedUUID;
	String RandomSeed; 
	String WinningHash;
	//Data to be read in
	String Fname;
	String Lname;
	String SSNum;
	String DOB;
	String Diag;
	String Treat;
	String Rx;

	//Accessor and mutator methods for the block class
	public String getBlockID() {return BlockID;}
	public void setBlockID(String BID){this.BlockID = BID;}

	public String getTimeStamp() {return TimeStamp;}
	public void setTimeStamp(String TS){this.TimeStamp = TS;}

	public String getCreatingProcessID() {return CreatingProcessID;}
	public void setCreatingProcessID(String PID) {this.CreatingProcessID = PID;}

	public String getVerificationProcessID() {return VerificationProcessID;}
	public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}

	public String getPreviousHash() {return this.PreviousHash;}
	public void setPreviousHash (String PH){this.PreviousHash = PH;}

	public UUID getUUID() {return uuid;} 
	public void setUUID (UUID ud){this.uuid = ud;}

	public String getSignedUUID() {return signedUUID;}
	public void  setSignedUUID(String SU) {this.signedUUID = SU;}

	public String getLname() {return Lname;}
	public void setLname (String LN){this.Lname = LN;}

	public String getFname() {return Fname;}
	public void setFname (String FN){this.Fname = FN;}

	public String getSSNum() {return SSNum;}
	public void setSSNum (String SS){this.SSNum = SS;}

	public String getDOB() {return DOB;}
	public void setDOB (String RS){this.DOB = RS;}

	public String getDiag() {return Diag;}
	public void setDiag (String D){this.Diag = D;}

	public String getTreat() {return Treat;}
	public void setTreat (String Tr){this.Treat = Tr;}

	public String getRx() {return Rx;}
	public void setRx (String Rx){this.Rx = Rx;}

	public String getRandomSeed() {return RandomSeed;}
	public void setRandomSeed (String RS){this.RandomSeed = RS;}

	public String getWinningHash() {return WinningHash;}
	public void setWinningHash (String WH){this.WinningHash = WH;}
}
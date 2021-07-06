package Java;
import java.math.BigInteger;
import java.util.Arrays;
public class TWINE {

	final static int[] SubBox= new int[]{

			0xC,0x0,0xF,0xA,0x2,0xB,0x9,0x5,0x8,0x3,0xD,0x7,0x1,0xE,0x6,0x4
	};

	final static int[] ShuffleArray= new int[] {
			5,0,1,4,7,12,3,8,13,6,9,2,15,10,11,14
	};
	final static int[] InverseShuffleArray= new int[] {
			1,2,11,6,3,0,9,4,7,10,13,14,5,8,15,12
	};
	final static int[] Constants=new int[] {
			0x01,0x02,0x04,0x08,0x10,0x20,0x03,0x06,0x0C,0x18,0x30,0x23,
			0x05,0x0A,0x14,0x28,0x13,0x26,0x0F,0x1E,0x3C,0x3B,0x35,0x29,
			0x11,0x22,0x07,0x0E,0x1C,0x38,0x33,0x25,0x09,0x12,0x24,0x0B

	};

	public static int[][] KeyScheduling(int[] key) {

		int[][] RoundKeys=new int[36][8];
		int[] KeyPartitions=new int[20];
		int tmp0, tmp1,tmp2,tmp3;

		//		for(int i=0;i<20;i++) {
		//			KeyPartitions[i]=(key[(i/4)];
		//			System.out.println(i);
		//
		//		}

		KeyPartitions[0]= ( key[0]>>(12) ) & 0x0F;
		KeyPartitions[1]= ( key[0]>>(8) ) & 0x0F;
		KeyPartitions[2]= ( key[0]>>(4) ) & 0x0F;
		KeyPartitions[3]= ( key[0]>>(0) ) & 0x0F;
		KeyPartitions[4]= ( key[1]>>(12) ) & 0x0F;
		KeyPartitions[5]= ( key[1]>>(8) ) & 0x0F;
		KeyPartitions[6]= ( key[1]>>(4) ) & 0x0F;
		KeyPartitions[7]= ( key[1]>>(0) ) & 0x0F;
		KeyPartitions[8]= ( key[2]>>(12) ) & 0x0F;
		KeyPartitions[9]= ( key[2]>>(8) ) & 0x0F;
		KeyPartitions[10]= ( key[2]>>(4) ) & 0x0F;
		KeyPartitions[11]= ( key[2]>>(0) ) & 0x0F;
		KeyPartitions[12]= ( key[3]>>(12) ) & 0x0F;
		KeyPartitions[13]= ( key[3]>>(8) ) & 0x0F;
		KeyPartitions[14]= ( key[3]>>(4) ) & 0x0F;
		KeyPartitions[15]= ( key[3]>>(0) ) & 0x0F;
		KeyPartitions[16]= ( key[4]>>(12) ) & 0x0F;
		KeyPartitions[17]= ( key[4]>>(8) ) & 0x0F;
		KeyPartitions[18]= ( key[4]>>(4) ) & 0x0F;
		KeyPartitions[19]= ( key[4]>>(0) ) & 0x0F;







		RoundKeys[0][0]=KeyPartitions[1];
		RoundKeys[0][1]=KeyPartitions[3];
		RoundKeys[0][2]=KeyPartitions[4];
		RoundKeys[0][3]=KeyPartitions[6];
		RoundKeys[0][4]=KeyPartitions[13];
		RoundKeys[0][5]=KeyPartitions[14];
		RoundKeys[0][6]=KeyPartitions[15];
		RoundKeys[0][7]=KeyPartitions[16];


		for(int i=1;i<36;i++) {
			KeyPartitions[1]=KeyPartitions[1] ^ SubBox[KeyPartitions[0]];
			KeyPartitions[4]=KeyPartitions[4] ^ SubBox[KeyPartitions[16]];
			KeyPartitions[7]=KeyPartitions[7] ^ ( Constants[i-1] >> 3 );
			KeyPartitions[19]=KeyPartitions[19] ^ ( Constants[i-1] & 0x07);

			tmp0=KeyPartitions[0];
			tmp1=KeyPartitions[1];
			tmp2=KeyPartitions[2];
			tmp3=KeyPartitions[3];

			for(int j=0;j<4;j++) {
				KeyPartitions[j*4]=KeyPartitions[j*4+4];
				KeyPartitions[j*4+1]=KeyPartitions[j*4+5];
				KeyPartitions[j*4+2]=KeyPartitions[j*4+6];
				KeyPartitions[j*4+3]=KeyPartitions[j*4+7];

			}
			KeyPartitions[16]=tmp1;
			KeyPartitions[17]=tmp2;
			KeyPartitions[18]=tmp3;
			KeyPartitions[19]=tmp0;

			RoundKeys[i][0]=KeyPartitions[1];
			RoundKeys[i][1]=KeyPartitions[3];
			RoundKeys[i][2]=KeyPartitions[4];
			RoundKeys[i][3]=KeyPartitions[6];
			RoundKeys[i][4]=KeyPartitions[13];
			RoundKeys[i][5]=KeyPartitions[14];
			RoundKeys[i][6]=KeyPartitions[15];
			RoundKeys[i][7]=KeyPartitions[16];
		}	
		return RoundKeys;
	}



	public static int[] TwineEncrypt(int[] Plaintext, int[][] RoundKey) {
		int[] X=Arrays.copyOf(Plaintext, Plaintext.length);
		int[] tempArray=new int[16];

		for(int i=0;i<35;i++) {
			for(int j=0;j<8;j++) {
				X[2*j+1]=( SubBox[ ( X[2*j] ) ^ ( RoundKey[i][j] ) ] ) ^ (X[2*j+1]);
			}

			for(int h=0;h<16;h++) {
				tempArray[ShuffleArray[h]]=X[h];
			}

//			System.out.println();
//			System.out.print("Enryption Round " + (i+1) +": " );
			for(int h=0;h<16;h++) {
				X[h]=tempArray[h];
//				System.out.print( Integer.toHexString(X[h]).toUpperCase());
			}
		}
		for (int i=0;i<=7;i++) {
			X[2*i+1]=SubBox[ X[2*i] ^ RoundKey[35][i] ] ^ X[2*i+1];
		}
//		System.out.println();
//		System.out.print("Enryption Round 36: " );
		for (int i=0;i<16;i++) {
//			System.out.print( Integer.toHexString(X[i]).toUpperCase());
		}

		return X;
	}
	public static int[] TwineDecrypt(int[] CipherText,int[][] RoundKey) {

		int[] Y=Arrays.copyOf(CipherText,CipherText.length);
		int[] tempArray=new int[16];
		for (int i=0;i<16;i++) {
//			System.out.print( Integer.toHexString(Y[i]).toUpperCase());
		}


		for(int i=35;i>0;i--) {
			for(int j=0;j<8;j++) {
				Y[2*j+1]=SubBox[ Y[2*j] ^ RoundKey[i][j] ] ^ Y[2*j+1];
			}

			for(int h=0;h<16;h++) {
				tempArray[InverseShuffleArray[h]]=Y[h];
			}
//			System.out.println();
//			System.out.print("Decryption Round " + (i+1) +": " );
			for(int h=0;h<16;h++) {
				Y[h]=tempArray[h];
//				System.out.print( Integer.toHexString(Y[h]).toUpperCase());

			}
		}
		for (int i=0;i<=7;i++) {
			Y[2*i+1]=SubBox[ Y[2*i] ^ RoundKey[0][i] ] ^ Y[2*i+1];

		}
//		System.out.println();
//		System.out.print("Deryption Round 1: " );
		for (int i=0;i<16;i++) {
//			System.out.print( Integer.toHexString(Y[i]).toUpperCase());
		}

		return Y;
	}






	public static void main(String []args) {

		int[] Plain=new int[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

		int[] Key=new int[] {
				0x0011, 0x2233, 0x4455, 0x6677, 0x8899

		};


		int[][] RoundKeys=KeyScheduling(Key);
		System.out.println("Plaintext is: ");
		for(int i=0;i<16;i++) {
			System.out.print(""+Integer.toHexString(Plain[i]).toUpperCase()+"");
		}
		int[] Cipher=TwineEncrypt(Plain, RoundKeys);



		System.out.println("\n \nEncryption: ");

		for(int i=0;i<16;i++) {
			System.out.print(""+ Integer.toHexString(Cipher[i]).toUpperCase()+"");
		}

//		System.out.println();
//		System.out.println();


		int[] PlainD=TwineDecrypt(Cipher,RoundKeys);
		System.out.println("\n \nDecryption:");
		for(int i=0;i<16;i++) {

			System.out.print(""+Integer.toHexString(PlainD[i]).toUpperCase()+"");
		}
	}
}

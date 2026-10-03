/*
input: byte[] array
output: byte[] array
 */
public class AES { //256
    private final byte[] key;
    private final byte[] plainText;

    private static final int NB = 4;
    private static final int NK = 8;
    private static final int NR = 14;
    private byte[] cipherText = new byte[0];
    private final byte[][] state = new byte[4][4];

    private final static byte[][] SBox =
        {
            {0x63,0x7c,0x77,0x7b,(byte)0xf2,0x6b,0x6f,(byte)0xc5,0x30,0x01,0x67,0x2b,(byte)0xfe,(byte)0xd7,(byte)0xab,0x76},
            {(byte)0xca,(byte)0x82,(byte)0xc9,0x7d,(byte)0xfa,0x59,0x47,(byte)0xf0,(byte)0xad,(byte)0xd4,(byte)0xa2,(byte)0xaf,(byte)0x9c,(byte)0xa4,0x72,(byte)0xc0},
            {(byte)0xb7,(byte)0xfd,(byte)0x93,0x26,0x36,0x3f,(byte)0xf7,(byte)0xcc,0x34,(byte)0xa5,(byte)0xe5,(byte)0xf1,0x71,(byte)0xd8,0x31,0x15},
            {0x04,(byte)0xc7,0x23,(byte)0xc3,0x18,(byte)0x96,0x05,(byte)0x9a,0x07,0x12,(byte)0x80,(byte)0xe2,(byte)0xeb,0x27,(byte)0xb2,0x75},
            {0x09,(byte)0x83,0x2c,0x1a,0x1b,0x6e,0x5a,(byte)0xa0,0x52,0x3b,(byte)0xd6,(byte)0xb3,0x29,(byte)0xe3,0x2f,(byte)0x84},
            {0x53,(byte)0xd1,0x00,(byte)0xed,0x20,(byte)0xfc,(byte)0xb1,0x5b,0x6a,(byte)0xcb,(byte)0xbe,0x39,0x4a,0x4c,0x58,(byte)0xcf},
            {(byte)0xd0,(byte)0xef,(byte)0xaa,(byte)0xfb,0x43,0x4d,0x33,(byte)0x85,0x45,(byte)0xf9,0x02,0x7f,0x50,0x3c,(byte)0x9f,(byte)0xa8},
            {0x51,(byte)0xa3,0x40,(byte)0x8f,(byte)0x92,(byte)0x9d,0x38,(byte)0xf5,(byte)0xbc,(byte)0xb6,(byte)0xda,0x21,0x10,(byte)0xff,(byte)0xf3,(byte)0xd2},
            {(byte)0xcd,0x0c,0x13,(byte)0xec,0x5f,(byte)0x97,0x44,0x17,(byte)0xc4,(byte)0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
            {0x60,(byte)0x81,0x4f,(byte)0xdc,0x22,0x2a,(byte)0x90,(byte)0x88,0x46,(byte)0xee,(byte)0xb8,0x14,(byte)0xde,0x5e,0x0b,(byte)0xdb},
            {(byte)0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,(byte)0xc2,(byte)0xd3,(byte)0xac,0x62,(byte)0x91,(byte)0x95,(byte)0xe4,0x79},
            {(byte)0xe7,(byte)0xc8,0x37,0x6d,(byte)0x8d,(byte)0xd5,0x4e,(byte)0xa9,0x6c,0x56,(byte)0xf4,(byte)0xea,0x65,0x7a,(byte)0xae,0x08},
            {(byte)0xba,0x78,0x25,0x2e,0x1c,(byte)0xa6,(byte)0xb4,(byte)0xc6,(byte)0xe8,(byte)0xdd,0x74,0x1f,0x4b,(byte)0xbd,(byte)0x8b,(byte)0x8a},
            {0x70,0x3e,(byte)0xb5,0x66,0x48,0x03,(byte)0xf6,0x0e,0x61,0x35,0x57,(byte)0xb9,(byte)0x86,(byte)0xc1,0x1d,(byte)0x9e},
            {(byte)0xe1,(byte)0xf8,(byte)0x98,0x11,0x69,(byte)0xd9,(byte)0x8e,(byte)0x94,(byte)0x9b,0x1e,(byte)0x87,(byte)0xe9,(byte)0xce,0x55,0x28,(byte)0xdf},
            {(byte)0x8c,(byte)0xa1,(byte)0x89,0x0d,(byte)0xbf,(byte)0xe6,0x42,0x68,0x41,(byte)0x99,0x2d,0x0f,(byte)0xb0,0x54,(byte)0xbb,0x16}
        };
    private final static byte[][] invSBox =
        {
            {0x52,0x09,0x6a,(byte)0xd5,0x30,0x36,(byte)0xa5,0x38,(byte)0xbf,0x40,(byte)0xa3,(byte)0x9e,(byte)0x81,(byte)0xf3,(byte)0xd7,(byte)0xfb},
            {0x7c,(byte)0xe3,0x39,(byte)0x82,(byte)0x9b,0x2f,(byte)0xff,(byte)0x87,0x34,(byte)0x8e,0x43,0x44,(byte)0xc4,(byte)0xde,(byte)0xe9,(byte)0xcb},
            {0x54,0x7b,(byte)0x94,0x32,(byte)0xa6,(byte)0xc2,0x23,0x3d,(byte)0xee,0x4c,(byte)0x95,0x0b,0x42,(byte)0xfa,(byte)0xc3,0x4e},
            {0x08,0x2e,(byte)0xa1,0x66,0x28,(byte)0xd9,0x24,(byte)0xb2,0x76,0x5b,(byte)0xa2,0x49,0x6d,(byte)0x8b,(byte)0xd1,0x25},
            {0x72,(byte)0xf8,(byte)0xf6,0x64,(byte)0x86,0x68,(byte)0x98,0x16,(byte)0xd4,(byte)0xa4,0x5c,(byte)0xcc,0x5d,0x65,(byte)0xb6,(byte)0x92},
            {0x6c,0x70,0x48,0x50,(byte)0xfd,(byte)0xed,(byte)0xb9,(byte)0xda,0x5e,0x15,0x46,0x57,(byte)0xa7,(byte)0x8d,(byte)0x9d,(byte)0x84},
            {(byte)0x90,(byte)0xd8,(byte)0xab,0x00,(byte)0x8c,(byte)0xbc,(byte)0xd3,0x0a,(byte)0xf7,(byte)0xe4,0x58,0x05,(byte)0xb8,(byte)0xb3,0x45,0x06},
            {(byte)0xd0,0x2c,0x1e,(byte)0x8f,(byte)0xca,0x3f,0x0f,0x02,(byte)0xc1,(byte)0xaf,(byte)0xbd,0x03,0x01,0x13,(byte)0x8a,0x6b},
            {0x3a,(byte)0x91,0x11,0x41,0x4f,0x67,(byte)0xdc,(byte)0xea,(byte)0x97,(byte)0xf2,(byte)0xcf,(byte)0xce,(byte)0xf0,(byte)0xb4,(byte)0xe6,0x73},
            {(byte)0x96,(byte)0xac,0x74,0x22,(byte)0xe7,(byte)0xad,0x35,(byte)0x85,(byte)0xe2,(byte)0xf9,0x37,(byte)0xe8,0x1c,0x75,(byte)0xdf,0x6e},
            {0x47,(byte)0xf1,0x1a,0x71,0x1d,0x29,(byte)0xc5,(byte)0x89,0x6f,(byte)0xb7,0x62,0x0e,(byte)0xaa,0x18,(byte)0xbe,0x1b},
            {(byte)0xfc,0x56,0x3e,0x4b,(byte)0xc6,(byte)0xd2,0x79,0x20,(byte)0x9a,(byte)0xdb,(byte)0xc0,(byte)0xfe,0x78,(byte)0xcd,0x5a,(byte)0xf4},
            {0x1f,(byte)0xdd,(byte)0xa8,0x33,(byte)0x88,0x07,(byte)0xc7,0x31,(byte)0xb1,0x12,0x10,0x59,0x27,(byte)0x80,(byte)0xec,0x5f},
            {0x60,0x51,0x7f,(byte)0xa9,0x19,(byte)0xb5,0x4a,0x0d,0x2d,(byte)0xe5,0x7a,(byte)0x9f,(byte)0x93,(byte)0xc9,(byte)0x9c,(byte)0xef},
            {(byte)0xa0,(byte)0xe0,0x3b,0x4d,(byte)0xae,0x2a,(byte)0xf5,(byte)0xb0,(byte)0xc8,(byte)0xeb,(byte)0xbb,0x3c,(byte)0x83,0x53,(byte)0x99,0x61},
            {0x17,0x2b,0x04,0x7e,(byte)0xba,0x77,(byte)0xd6,0x26,(byte)0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d}
        };

    private static final byte[] rcon = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte)0x80, 0x1b, 0x36
    };

    public AES(byte[] key, byte[] plainText){
        if (key.length != 32) { //aes256
            throw new IllegalArgumentException("AES-256 key must be 32 bytes");
        }else {
            this.key = key;
        }
        this.plainText = plainText;
    }

    private void printState(){
        for(int i = 0; i < this.state.length;i++){
            for(int n = 0; n < this.state[0].length;n++){
                System.out.printf("%02x ",(this.state[i][n] & 0xFF));
            }
            System.out.print("\n");
        }
    }


//================================ KEYEXPANSION ================================

    private static int rotWord(int word) {
        return (word << 8) | (word >>> 24);
    }
    private int subWord(int word){
        int b0 = (word >>> 24) & 0xFF;//leading byte
        int b1 = (word >>> 16) & 0xFF;
        int b2 = (word >>> 8)  & 0xFF;
        int b3 =  word         & 0xFF;

        int s0 = SBox[b0 >>> 4][b0 & 0x0F] & 0xFF;
        int s1 = SBox[b1 >>> 4][b1 & 0x0F] & 0xFF;
        int s2 = SBox[b2 >>> 4][b2 & 0x0F] & 0xFF;
        int s3 = SBox[b3 >>> 4][b3 & 0x0F] & 0xFF;

        return (s0 << 24) | (s1 << 16) | (s2 << 8) | s3;
    }

    private static int makeWord(byte[] bytes, int offset) {//word as INT
        return ((bytes[offset] & 0xFF) << 24) |
                ((bytes[offset + 1] & 0xFF) << 16) |
                ((bytes[offset + 2] & 0xFF) << 8)  |
                ((bytes[offset + 3] & 0xFF));
    }

    private static void extractWord(int word, byte[] bytes, int offset) {//32bit from int to 4 bytes
        bytes[offset]     = (byte) (word >>> 24);
        bytes[offset + 1] = (byte) (word >>> 16);
        bytes[offset + 2] = (byte) (word >>> 8);
        bytes[offset + 3] = (byte) (word);
    }

    private byte[] keyExpansion(){
        int totalWords = 4*(NR +1);//60
        int[] w = new int[totalWords];


        for(int i = 0; i<= NK -1; i++){
            w[i] = makeWord(this.key, 4 * i);//4 byte word as INT
        }

        for (int i = NK; i < 4* NR +3+1; i++) {//4*nr+3 equals 59 instead of 60, thats why +1
            int temp = w[i - 1];

            if (i % NK == 0) {
                temp = subWord(rotWord(temp))^((rcon[i / NK - 1] & 0xFF) << 24);
                //nk-1: rcon array starts from [0] index
                //<<24: from 00 00 00 01 (byte as int) to 01 00 00 00 (like in aes docs)
            } else if ((i % NK == 4)) {
                temp = subWord(temp);
            }

            w[i] = w[i - NK] ^ temp;
        }

        byte[] expandedKey = new byte[totalWords * 4];
        for (int i = 0; i < totalWords; i++) {
            extractWord(w[i], expandedKey, 4 * i);
        }

        return expandedKey;
    }

//================================ end KEYEXPANSION ================================

    private void addRoundKey(int round, byte[] expandedKey){
        int offset = round * 16;
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                this.state[row][col] ^= expandedKey[offset + col * 4 + row];
            }
        }
    }

    private void subBytes(){
        for(int i=0;i<this.state.length;i++) {
            for(int n=0;n<this.state[0].length;n++) {
                int row = (this.state[i][n] >>> 4) & 0x0F;
                int column = this.state[i][n] & 0x0F;

                this.state[i][n] = SBox[row][column];

            }
        }
    }

    private void shiftRows(){
        byte temp1,temp2,temp3;

        temp1 = this.state[1][0];
        this.state[1][0]=this.state[1][1];
        this.state[1][1]=this.state[1][2];
        this.state[1][2]=this.state[1][3];
        this.state[1][3]=temp1;

        temp1 = this.state[2][0];
        temp2 = this.state[2][1];
        this.state[2][0]=this.state[2][2];
        this.state[2][1]=this.state[2][3];
        this.state[2][2]=temp1;
        this.state[2][3]=temp2;

        temp1 = this.state[3][0];
        temp2 = this.state[3][1];
        temp3 = this.state[3][2];
        this.state[3][0]=this.state[3][3];
        this.state[3][1]=temp1;
        this.state[3][2]=temp2;
        this.state[3][3]=temp3;
    }

//================================ MIXCOLUMNS ================================

    private int mulByTwo(int num){
        int highBit = (num >>> 7); //& 1 ????
        int mask = highBit * 0x1B;
        //if highBit == 1 then mask should be 0x1B (as part of a reduction)
        //if highBit == 0 then mask should be 0x00
        return ((num<<1)^mask)&0xFF;
    }

    private int mulByThree(int num){
        return(mulByTwo(num)^num);
    }

    private void mixColumns(){
        for(int c = 0;c<this.state[0].length;c++){
            int s0 = this.state[0][c] & 0xFF;
            int s1 = this.state[1][c] & 0xFF;
            int s2 = this.state[2][c] & 0xFF;
            int s3 = this.state[3][c] & 0xFF;

            this.state[0][c] = (byte) ((mulByTwo(s0)^mulByThree(s1)^s2^s3) & 0xFF);
            this.state[1][c] = (byte) ((s0^mulByTwo(s1)^mulByThree(s2)^s3) & 0xFF);
            this.state[2][c] = (byte) ((s0^s1^mulByTwo(s2)^mulByThree(s3)) & 0xFF);
            this.state[3][c] = (byte) ((mulByThree(s0)^s1^s2^mulByTwo(s3)) & 0xFF);
        }
//        {
//            {0x02,0x03,0x01,0x01},
//            {0x01,0x02,0x03,0x01},
//            {0x01,0x01,0x02,0x03},
//            {0x03,0x01,0x01,0x02},
//        };
    }

//================================ end MIXCOLUMNS ================================

    private void cipher(int rep, byte[] expandedKey){
        //state <- in
        for(int i = 0; i < this.state[0].length;i++){
            for(int n = 0; n < this.state.length;n++){
                this.state[n][i]=this.plainText[rep*16+i*this.state.length+n];//by columns
            }
        }

        addRoundKey(0,expandedKey);

        for(int i = 1; i < NR; i++){
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(i,expandedKey);
        }

        subBytes();
        shiftRows();
        addRoundKey(NR,expandedKey);
    }
//================================ end CIPHER ================================

    private void invShiftRows(){
        byte temp1,temp2;

        temp1 = this.state[1][0];
        this.state[1][0]=this.state[1][3];
        this.state[1][3]=this.state[1][2];
        this.state[1][2]=this.state[1][1];
        this.state[1][1]=temp1;

        temp1 = this.state[2][0];
        temp2 = this.state[2][1];
        this.state[2][0]=this.state[2][2];
        this.state[2][1]=this.state[2][3];
        this.state[2][2]=temp1;
        this.state[2][3]=temp2;

        temp1 = this.state[3][0];
        this.state[3][0]=this.state[3][1];
        this.state[3][1]=this.state[3][2];
        this.state[3][2]=this.state[3][3];
        this.state[3][3]=temp1;
    }

    private void invSubBytes(){
        for(int i=0;i<this.state.length;i++) {
            for(int n=0;n<this.state[0].length;n++) {
                int row = (this.state[i][n] >>> 4) & 0x0F;
                int column = this.state[i][n] & 0x0F;

                this.state[i][n] = invSBox[row][column];

            }
        }
    }
//================================ INVMIXCOLUMNS ================================
    private int mulByFour(int num){
        return (mulByTwo(mulByTwo(num)));
    }

    private int mulByEight(int num){
        return (mulByTwo(mulByFour(num)));
    }
    private int mulByNine(int num){
        return (mulByEight(num)^num);
    }

    private int mulBy0B(int num){//11
        return (mulByEight(num)^mulByTwo(num)^num);
    }

    private int mulBy0D(int num){//13
        return (mulByEight(num)^mulByFour(num)^num);
    }

    private int mulBy0E(int num){//14
        return (mulByEight(num)^mulByFour(num)^mulByTwo(num));
    }
    private void invMixColumns(){
        for(int c = 0;c<this.state[0].length;c++){
            int s0 = this.state[0][c] & 0xFF;
            int s1 = this.state[1][c] & 0xFF;
            int s2 = this.state[2][c] & 0xFF;
            int s3 = this.state[3][c] & 0xFF;

            this.state[0][c] = (byte) ((mulBy0E(s0)^mulBy0B(s1)^mulBy0D(s2)^mulByNine(s3)) & 0xFF);
            this.state[1][c] = (byte) ((mulByNine(s0)^mulBy0E(s1)^mulBy0B(s2)^mulBy0D(s3)) & 0xFF);
            this.state[2][c] = (byte) ((mulBy0D(s0)^mulByNine(s1)^mulBy0E(s2)^mulBy0B(s3)) & 0xFF);
            this.state[3][c] = (byte) ((mulBy0B(s0)^mulBy0D(s1)^mulByNine(s2)^mulBy0E(s3)) & 0xFF);
            //powers of two should be used to perform correct multiplication
        }
    }
//================================ end INVMIXCOLUMNS ================================

    private void invCipher(int rep, byte[] expandedKey){
        //state <- in
        for(int i = 0; i < this.state[0].length;i++){
            for(int n = 0; n < this.state.length;n++){
                this.state[n][i]=this.plainText[rep*16+i*this.state.length+n];//by columns
            }
        }

        addRoundKey(NR,expandedKey);

        for(int i = NR-1; i >= 1; i--){
            invShiftRows();
            invSubBytes();
            addRoundKey(i,expandedKey);
            invMixColumns();
        }

        invShiftRows();
        invSubBytes();
        addRoundKey(0,expandedKey);
    }
//================================ end INVCIPHER ================================
    private void moveState(int rep){
        byte[] temp = new byte[(rep+1)*16];

        System.arraycopy(this.cipherText,0,temp,0,this.cipherText.length);

        for(int i = 0; i<this.state[0].length;i++){
            for(int n = 0; n<this.state.length;n++){
                temp[rep*16+i*this.state[0].length+n]=this.state[n][i];
            }
        }
        this.cipherText=temp;
    }

    public byte[] encrypt(){//ecb mode
        int reps = this.plainText.length / 16;

        byte[] expandedKey = keyExpansion();

        for(int i = 0; i < reps; i++){
            cipher(i,expandedKey);
            moveState(i);
        }
        return this.cipherText;
    }
    public byte[] decrypt(){//ECB mode
        int reps = this.plainText.length / 16;

        byte[] expandedKey = keyExpansion();

        for(int i = 0; i < reps; i++){
            invCipher(i,expandedKey);
            moveState(i);
        }
        return this.cipherText;
    }
}
/*
===== TEST =====
plain text:
46 69 6E 6C 61 6E 64 2C 20 6F 66 66 69 63 69 61 6C 6C 79 20 74 68 65 20 52 65 70 75 62 6C 69 63 20 6F 66 20 46 69 6E 6C
46696E6C616E642C206F6666696369616C6C79207468652052657075626C6963206F662046696E6C

encrypted:
9c 38 7f 4d 84 05 78 f2 8c 49 df 7b 16 9c 21 40 c8 02 4f 28 14 33 f7 96 0d a6 70 f9 01 04 31 f9 24 b0 b3 dc c3 d5 ca 28 a7 ff 75 36 48 33 3d ab
9c387f4d840578f28c49df7b169c2140c8024f281433f7960da670f9010431f924b0b3dcc3d5ca28a7ff753648333dab
 */
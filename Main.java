import java.util.Scanner;

public class Main {
    private static void validateData(String data){
        if (data.length()==0) throw new IllegalArgumentException("No data entered.");
        if (!data.matches("[0-9a-f]+")) throw new IllegalArgumentException("Not a hex.");
        if (data.length() % 2 != 0) throw new IllegalArgumentException("Data length must be even.");
    }

    public static byte[] hexToBytes(String data) {
        int len = data.length();
        byte[] byteData = new byte[len / 2];

        for (int i=0; i<byteData.length; i++) {
            byteData[i]=(byte) ((Character.digit(data.charAt(2*i), 16) << 4)
                    + Character.digit(data.charAt(2*i + 1), 16));
        }
        return byteData;
    }

    private static byte[] paddingFiller(byte[] byteData){
        int bdLen = byteData.length;
        int paddingLen = 16 - (bdLen % 16);//full 16byte block added to prevent payload deletion

        byte[] paddedArray = new byte[bdLen + paddingLen];
        System.arraycopy(byteData,0,paddedArray,0,byteData.length);

        for(int i = bdLen; i<bdLen+paddingLen;i++){
            paddedArray[i] = (byte)paddingLen;
        }

        return paddedArray;
    }

    private static byte[] paddingRemover(byte[] byteData){
        int bdLen = byteData.length;
        int paddingLen = byteData[bdLen - 1] & 0xFF;

        if (paddingLen == 0 || paddingLen > 16) {
            return byteData;
        }

        for (int i = 0; i < paddingLen; i++) {
            if ((byteData[bdLen - 1 - i] & 0xFF) != paddingLen) {
                return byteData; //incorrect padding detected
            }
        }

        byte[] cleanedArray = new byte[bdLen - paddingLen];
        System.arraycopy(byteData, 0, cleanedArray, 0, cleanedArray.length);
        return cleanedArray;
    }

    public static void main(String[] args) {
        final String key = "9bb5c9cde7df5fba2bfdba61ee0c21a01d91490c9d2fca54453300e0b264516d";//preamble SHA256
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter data in HEX:\n0x");
        String data = scanner.nextLine().trim().toLowerCase().replace(" ", "");
        System.out.print("\nEnter mode (1 - encrypt; 2 - decrypt):\n");
        int mode = scanner.nextInt();

        try{
            validateData(data);
            byte[] byteKey = hexToBytes(key);
            byte[] byteData = hexToBytes(data);
            byte[] c = null;

            //two instances of AES - bad
            if (mode == 1){
                System.out.print("Selected mode: encrypt\n");

                byteData = paddingFiller(byteData);
                AES aes = new AES(byteKey,byteData);
                c = aes.encrypt();

            } else if (mode == 2) {
                if(!(byteData.length%16==0)){
                    throw new IllegalArgumentException("Input data must be a multiple of 16.");
                }
                System.out.print("Selected mode: decrypt\n");

                AES aes = new AES(byteKey,byteData);
                c = paddingRemover(aes.decrypt());

            }else {
                throw new IllegalArgumentException("Wrong mode.");
            }

            System.out.println("\nResult:");
            for(int i=0;i<c.length;i++){
                System.out.printf("%02x ",(c[i] & 0xFF));
            }

        }catch (IllegalArgumentException e){
            System.out.println("Error: "+ e.getMessage());
        }

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
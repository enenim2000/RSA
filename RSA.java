package enenim.rsa;

/**
 * Implemented by Enenim Bassey
 */

import java.math.BigInteger;
import java.util.Random;

import static java.math.BigInteger.*;

public class RSA {
    private int messagePerLength = 200; //Ensure that string length is not greater than 200.
    private BigInteger p;
    private BigInteger q;
    private BigInteger e;
    private BigInteger d;
    private BigInteger n;

    public RSA(){
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(String pp) {
        BigInteger p = new BigInteger(pp);
        this.p = p;
    }

    public BigInteger getQ() {
        return q;
    }

    public void setQ(String qq) {
        BigInteger q = new BigInteger(qq);
        this.q = q;
    }

    public BigInteger getE() {
        return e;
    }

    public void setE(String ee) {
        BigInteger e = new BigInteger(ee);
        this.e = e;
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(String dd) {
        BigInteger d = new BigInteger(dd);
        this.d = d;
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public String encryptMessage(String message){
        return encrypt(message) ;
    }

    public String decryptCipher(String cipher){
        return decrypt(cipher);
    }

    public String encrypt(String msg){
        String[] message = encodeMsg(msg);
        String tmp = "";
        for(int i = 0; i < message.length; i++){
            if(i+1 < message.length)
                tmp = tmp + new BigInteger(message[i].getBytes()).modPow(getE(), getN()).toString() + " ";
            else
                tmp = tmp + new BigInteger(message[i].getBytes()).modPow(getE(), getN()).toString();
        }
        return tmp;
    }

    public String decrypt(String cipher){
        String temp = "";
        byte[] c;
        String[] cipherText = cipher.split(" ");
        for (int i = 0; i < cipherText.length; i++){
            c = new BigInteger(cipherText[i].trim()).toByteArray();
            temp = temp + new String( new BigInteger(c).modPow(getD(), getN()).toByteArray());
        }
        //temp is the decrypted message in number stored as string
        return temp;
    }

    public int getMessagePerLength() {
        return messagePerLength;
    }

    public void setMessagePerLength(int messagePerLength) {
        this.messagePerLength = messagePerLength;
    }

    /**
     *
     * If message is greater than specified length say 200
     * break it into sub messages each of length 200 except
     * the last part which might be 200 or less
     *
     */
    public String[] encodeMsg(String message){
        int k = 0;
        int index;
        if(message.length() % getMessagePerLength() == 0 ){
            index = message.length()/getMessagePerLength();
        }else {
            index = (int) Math.floor(message.length()/getMessagePerLength());
            index = index + 1;
        }
        String[] temp = new String[index] ;
        if(message.length() <= getMessagePerLength()){
            temp[k++] = message;
            return temp;
        }
        else {
            for(int i = 0; i < index; i++){
                if( i+1 < index)
                    temp[k++] = message.substring( getMessagePerLength()*i, getMessagePerLength()*(i+1) );
                else
                    temp[k++] = message.substring( getMessagePerLength()*i, message.length() );
            }

            return temp;
        }
    }

    /**
     *
     *
     Choose p = 3 and q = 11
     Compute n = p * q = 3 * 11 = 33
     Compute φ(n) = (p - 1) * (q - 1) = 2 * 10 = 20
     Choose e such that 1 < e < φ(n) and e and n are coprime. Let e = 7
     Compute a value for d such that (d * e) % φ(n) = 1. One solution is d = 3 [(3 * 7) % 20 = 1]
     Public key is (e, n) => (7, 33)
     Private key is (d, n) => (3, 33)
     The encryption of m = 2 is c = 27 % 33 = 29
     The decryption of c = 29 is m = 293 % 33 = 2
     */
    public void generateRSAParameters(){
        BigInteger phi;
        BigInteger e;
        BigInteger n;
        BigInteger p;
        BigInteger q;
        Random r;
        int bitLength = 1024; //typically between 1024 to 4096 for generating key sizes

        r = new Random();
        p = probablePrime(bitLength, r); //choose p
        q = probablePrime(bitLength, r); //choose q
        n = p.multiply(q); //Compute n = p * q
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); //Compute φ(n) = (p - 1) * (q - 1)
        e = probablePrime(bitLength / 2, r); //Public key is e and n
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0)
        {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(phi); //d // Private key is d and n x.modInverse(y) means x^-1 % y

        System.out.println("pp: " + p);
        System.out.println("qq: " + q);
        System.out.println("ee: " + e);
        System.out.println("dd: " + d);
    }
}

package cn.edu.buaa.crypto;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Weiran Liu on 15-9-30.
 */

public class Utils {
    private static final int default_block_size = 1024;

    public static PropertiesParameters GeneratePropertiesParameters(int rBitLength, int qBitLength) {
        PropertiesParameters parameters;
        Pairing pairing;
        Element g;

        // Generate curve parameters
        while (true) {
            parameters = generateCurveParams(rBitLength, qBitLength);
            pairing = PairingFactory.getPairing(parameters);
            g = pairing.getG1().newRandomElement().getImmutable();
            if (!pairing.pairing(g, g).isOne()) { return parameters; }
        }
    }

    private static PropertiesParameters generateCurveParams(int rBitLength, int qBitLength) {
        PairingParametersGenerator parametersGenerator = new TypeACurveGenerator(rBitLength, qBitLength);
        return (PropertiesParameters) parametersGenerator.generate();
    }


    /**
     * A standard collision resistant hash function implementations used privately for Map.
     * The used hash function depends on the security parameter of the pairing-based cryptography system.
     * If the security parameter is less than 256, we choose SHA-256;
     * If the security parameter is greater than 256, but less than 384, we choose SHA-384;
     * If the security parameter is greater than 384, we choose SHA-512;
     * @param bitLength security parameter of the underlying cryptography system
     * @param message mmessage to be hashed
     * @return hash result
     */
    private static byte[] hash(int bitLength, byte[] message) {
        MessageDigest md = null;
        try {
            if (bitLength <= 256) {
                md = MessageDigest.getInstance("SHA-256");
            } else if (bitLength <= 384) {
                md = MessageDigest.getInstance("SHA-384");
            } else if (bitLength <= 512) {
                md = MessageDigest.getInstance("SHA-512");
            } else {
                md = MessageDigest.getInstance("SHA-512");
            }
        } catch (NoSuchAlgorithmException e) {
            //Impossible to get this exception
            e.printStackTrace();
        }
        md.update(message);
        return md.digest();
    }

    /**
     * Map a byte array to Element in Zr
     * @param pairing pairing of the underlying cryptography system
     * @param message message to be hashed
     * @return Zr Element mapping the message
     */
    public static Element MapToZr(Pairing pairing, byte[] message) {
        byte[] shaResult = hash(512, message);
        Element hash = pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
        return hash;
    }

    public static Element MapToFirstHalfZr(Pairing pairing, byte[] message) {
        byte[] shaResult = hash(512, message);
        shaResult[0] = (byte) (shaResult[0] & 0xFE);
        Element hash = pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
        return hash;
    }

    public static Element MapToSecondHalfZr(Pairing pairing, byte[] message) {
        byte[] shaResult = hash(512, message);
        shaResult[0] = (byte) (shaResult[0] ^ 0x01);
        Element hash = pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
        return hash;
    }

    /**
     * Map a String to Element in Zr
     * @param pairing pairing of the underlying cryptography system
     * @param message message to be hashed
     * @return Zr Element mapping the message
     */
    public static Element MapToZr(Pairing pairing, String message) {
        return MapToZr(pairing, message.getBytes());
    }

    public static Element MapToFirstHalfZr(Pairing pairing, String message) { return MapToFirstHalfZr(pairing, message.getBytes()); }

    /**
     * Map several byte arrays to Elements in Zr
     * @param pairing pairing of the underlying cryptography system
     * @param message messages to be hashed
     * @return Zr Element arrays mapping the messages
     */
    public static Element[] MapToZr(Pairing pairing, byte[][] message){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            elements[i] = Utils.MapToZr(pairing, message[i]);
        }
        return elements;
    }

    public static Element[] MapToFirstHalfZr(Pairing pairing, byte[][] message){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            elements[i] = Utils.MapToFirstHalfZr(pairing, message[i]);
        }
        return elements;
    }

    /**
     * Map a String array to Elements in Zr
     * @param pairing pairing of the underlying cryptography system
     * @param message messages to be hashed
     * @return Zr Element arrays mapping the messages
     */
    public static Element[] MapToZr(Pairing pairing, String[] message){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            elements[i] = Utils.MapToZr(pairing, message[i]);
        }
        return elements;
    }

    public static Element[] MapToFirstHalfZr(Pairing pairing, String[] message){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            elements[i] = Utils.MapToFirstHalfZr(pairing, message[i]);
        }
        return elements;
    }

    /**
     * Map a byte array to Element in G1
     * @param pairing pairing of the underlying cryptography system
     * @param message message to be hashed
     * @return G1 Element mapping the message
     */
    public static Element MapToG1(Pairing pairing, byte[] message) {
        byte[] shaResult = hash(512, message);
        Element hash = pairing.getG1().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
        return hash;
    }

    /**
     * Map several byte arrays to Elements in G1
     * @param pairing pairing of the underlying cryptography system
     * @param message messages to be hashed
     * @return G1 Element arrays mapping the messages
     */
    public static Element[] MapToG1(Pairing pairing, byte[][] message){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            elements[i] = Utils.MapToG1(pairing, message[i]);
        }
        return elements;
    }

    /**
     * Map a byte array to Element in G2
     * @param pairing pairing of the underlying cryptography system
     * @param message message to be hashed
     * @return G2 Element mapping the message
     */
    public static Element MapToG2(Pairing pairing, byte[] message){
        byte[] shaResult = hash(512, message);
        Element hash = pairing.getG2().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
        return hash;
    }

    /**
     * Map several byte arrays to Elements in G2
     * @param pairing pairing of the underlying cryptography system
     * @param message messages to be hashed
     * @return G2 Element arrays mapping the messages
     */
    public static Element[] MapToG2(Pairing pairing, byte[][] message){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            elements[i] = Utils.MapToG2(pairing, message[i]);
        }
        return elements;
    }

    /**
     * Map a byte array to Element in GT
     * @param pairing pairing of the underlying cryptography system
     * @param message message to be hashed
     * @return GT Element mapping the message
     */
    public static Element MapToGT(Pairing pairing, byte[] message){
        byte[] shaResult = hash(512, message);
        Element hash = pairing.getGT().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
        return hash;
    }

    /**
     * Map several byte arrays to Elements in GT
     * @param pairing pairing of the underlying cryptography system
     * @param message messages to be hashed
     * @return GT Element arrays mapping the messages
     */
    public static Element[] MapToGT(Pairing pairing, byte[][] message){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            elements[i] = Utils.MapToGT(pairing, message[i]);
        }
        return elements;
    }

    public static boolean isEqualElement(final Element thisElement, final Element thatElement) {
        if (thisElement == thatElement) {
            return true;
        }
        String stringThisElement = new String(Hex.encode(thisElement.toBytes()));
        String stringThatElement = new String(Hex.encode(thatElement.toBytes()));
        return (stringThisElement.equals(stringThatElement));
    }

    public static boolean isEqualElementArray(final Element[] thisElementArray, final Element[] thatElementArray) {
        if (thisElementArray == thatElementArray) {
            return true;
        }
        if (thisElementArray.length != thatElementArray.length) {
            return false;
        }
        for (int i=0; i<thisElementArray.length; i++){
            if (!(Utils.isEqualElement(thisElementArray[i], thatElementArray[i]))){
                return false;
            }
        }
        return true;
    }
}

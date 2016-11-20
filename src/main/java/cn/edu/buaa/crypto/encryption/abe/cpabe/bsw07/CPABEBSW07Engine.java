package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.CPABEEngine;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE engine.
 */
public class CPABEBSW07Engine extends CPABEEngine {
    //Scheme name, used for exceptions
    private static final String SCHEME_NAME = "Bethencourt-Sahai-Wtaers large-universe CP-ABE KP-ABE";

    private static CPABEBSW07Engine engine;

    public static CPABEBSW07Engine getInstance() {
        if (engine == null) {
            engine = new CPABEBSW07Engine();
        }
        return engine;
    }

    private CPABEBSW07Engine() {

    }

    public String getEngineName() {
        return SCHEME_NAME;
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        return null;
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        return null;
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        return null;
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        return new byte[0];
    }
}

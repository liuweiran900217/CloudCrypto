package cn.edu.buaa.crypto.application.qlw17;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/7/20.
 *
 * This is the prototype of the Revocable Fast Outsourcing-Data Encryption (RFODE) scheme.
 * Conference version: B. Qin, W. Liu, Q. Wu, Z. Liang. Revocable Fast Outsourcing-Data Encapsulation
 *     with Fine-Grained Acess Control and Public Filtering for EHR Storages in Public Cloud.
 *     Submitted to INFOCOM 2017.
 */
public class RFODEQLW17Engine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Qin-Liu-Wu-RFODE";
    // Default strength for KeyPairGenerator, useless in Pairing based cryptography
    public static final int STENGTH = 12;

    //Employed Chameleon hash Engine
    private CHEngine chEngine;
    //Employed Access Control Implementation Engine
    private AccessControlEngine accessControlEngine;

    public RFODEQLW17Engine(AccessControlEngine accessControlEngine, CHEngine chEngine) {
        this.accessControlEngine = accessControlEngine;
        this.chEngine = chEngine;
    }

    public AsymmetricCipherKeyPair Setup(int rBitLength, int qBitLength) {
        return null;
    }

    public CipherParameters ACGen(CipherParameters publicKey, CipherParameters masterKey, String[] attributeSet) {
        return null;
    }

    public PairingKeyEncapsulationPair DataEncPreparation(CipherParameters publicKey, int n) {
        return null;
    }

    public PairingKeyEncapsulationPair DataEncRealTimeEncapsulation(CipherParameters publicKey, PairingCiphertextParameters intermediateCiphertext) {
        return null;
    }

    public PairingKeyEncapsulationPair DataEnc(CipherParameters publicKey, String[] attributeSet) {
        return null;
    }

    public boolean EncFilt(CipherParameters publicKey, CipherParameters ciphertext) {
        return false;
    }

    public byte[] DataDec(CipherParameters publicKey,  CipherParameters secretKey, CipherParameters ciphertext) {
        return null;
    }
}

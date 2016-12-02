package cn.edu.buaa.crypto.encryption.ibe.gen06b;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.generators.IBEGen06bDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.generators.IBEGen06bEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.generators.IBEGen06bKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.generators.IBEGen06bSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.*;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CCA2-secure IBE engine.
 */
public class IBEGen06bEngine extends IBEEngine {
    //Scheme name, used for exceptions
    private static final String SCHEME_NAME = "Gentry-06 CCA2-secure IBE scheme";

    private static IBEGen06bEngine engine;

    public static IBEGen06bEngine getInstance() {
        if (engine == null) {
            engine = new IBEGen06bEngine();
        }
        return engine;
    }

    private IBEGen06bEngine() { super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CCA2, PredicateSecLevel.ANON); }

    public PairingKeySerPair setup(PairingParameters pairingParameters) {
        IBEGen06bKeyPairGenerator keyPairGenerator = new IBEGen06bKeyPairGenerator();
        keyPairGenerator.init(new IBEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {
        if (!(publicKey instanceof IBEGen06bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEGen06bPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof IBEGen06bMasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + IBEGen06bMasterSecretKeySerParameter.class.getName());
        }
        IBEGen06bSecretKeyGenerator secretKeyGenerator = new IBEGen06bSecretKeyGenerator();
        secretKeyGenerator.init(new IBESecretKeyGenerationParameter(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String id){
        if (!(publicKey instanceof IBEGen06bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEGen06bPublicKeySerParameter.class.getName());
        }
        IBEGen06bEncryptionGenerator encryptionGenerator = new IBEGen06bEncryptionGenerator();
        encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String id, Element message){
        if (!(publicKey instanceof IBEGen06bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEGen06bPublicKeySerParameter.class.getName());
        }
        IBEGen06bEncryptionGenerator encryptionGenerator = new IBEGen06bEncryptionGenerator();
        encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String id, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBEGen06bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEGen06bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof IBEGen06bSecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + IBEGen06bSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof IBEGen06bCiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + IBEGen06bCiphertextSerParameter.class.getName());
        }
        IBEGen06bDecryptionGenerator decryptionGenerator = new IBEGen06bDecryptionGenerator();
        decryptionGenerator.init(new IBEDecryptionGenerationParameter(
                publicKey, secretKey, id, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String id, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBEGen06bPublicKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEGen06bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof IBEGen06bSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + IBEGen06bSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof IBEGen06bHeaderSerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME + ", find "
                            + header.getClass().getName() + ", require "
                            + IBEGen06bHeaderSerParameter.class.getName());
        }
        IBEGen06bDecryptionGenerator decryptionGenerator = new IBEGen06bDecryptionGenerator();
        decryptionGenerator.init(new IBEDecryptionGenerationParameter(
                publicKey, secretKey, id, header));
        return decryptionGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

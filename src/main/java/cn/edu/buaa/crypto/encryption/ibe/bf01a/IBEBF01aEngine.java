package cn.edu.buaa.crypto.encryption.ibe.bf01a;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.generators.IBEBF01aDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.generators.IBEBF01aEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.generators.IBEBF01aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.generators.IBEBF01aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.*;
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
 * Boneh-Franklin CPA-secure IBE engine.
 */
public class IBEBF01aEngine extends IBEEngine {
    //Scheme name, used for exceptions
    private static final String SCHEME_NAME = "Boneh-Franklin CPA-secure IBE scheme";

    private static IBEBF01aEngine engine;

    public static IBEBF01aEngine getInstance() {
        if (engine == null) {
            engine = new IBEBF01aEngine();
        }
        return engine;
    }

    private IBEBF01aEngine() {
        super(SCHEME_NAME, SecurityModel.RandomOracle, SecurityLevel.CPA);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters) {
        IBEBF01aKeyPairGenerator keyPairGenerator = new IBEBF01aKeyPairGenerator();
        keyPairGenerator.init(new IBEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {
        if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEBF01aPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof IBEBF01aMasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + IBEBF01aMasterSecretKeySerParameter.class.getName());
        }
        IBEBF01aSecretKeyGenerator secretKeyGenerator = new IBEBF01aSecretKeyGenerator();
        secretKeyGenerator.init(new IBESecretKeyGenerationParameter(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String id){
        if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEBF01aPublicKeySerParameter.class.getName());
        }
        IBEBF01aEncryptionGenerator encryptionGenerator = new IBEBF01aEncryptionGenerator();
        encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String id, Element message){
        if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEBF01aPublicKeySerParameter.class.getName());
        }
        IBEBF01aEncryptionGenerator encryptionGenerator = new IBEBF01aEncryptionGenerator();
        encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String id, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEBF01aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof IBEBF01aSecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + IBEBF01aSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof IBEBF01aCiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + IBEBF01aCiphertextSerParameter.class.getName());
        }
        IBEBF01aDecryptionGenerator decryptionGenerator = new IBEBF01aDecryptionGenerator();
        decryptionGenerator.init(new IBEDecryptionGenerationParameter(
                publicKey, secretKey, id, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String id, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBEBF01aPublicKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBEBF01aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof IBEBF01aSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + IBEBF01aSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof IBEBF01aHeaderSerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME + ", find "
                            + header.getClass().getName() + ", require "
                            + IBEBF01aHeaderSerParameter.class.getName());
        }
        IBEBF01aDecryptionGenerator decryptionGenerator = new IBEBF01aDecryptionGenerator();
        decryptionGenerator.init(new IBEDecryptionGenerationParameter(
                publicKey, secretKey, id, header));
        return decryptionGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

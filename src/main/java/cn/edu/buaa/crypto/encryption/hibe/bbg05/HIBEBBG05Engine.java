package cn.edu.buaa.crypto.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.*;
import cn.edu.buaa.crypto.encryption.hibe.genparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE engine.
 */
public class HIBEBBG05Engine implements HIBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Boneh-Boyen-Goh-05 HIBE scheme";

    private static HIBEBBG05Engine engine;

    public static HIBEBBG05Engine getInstance() {
        if (engine == null) {
            engine = new HIBEBBG05Engine();
        }
        return engine;
    }

    private HIBEBBG05Engine() {

    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxDepth) {
        HIBEBBG05KeyPairGenerator keyPairGenerator = new HIBEBBG05KeyPairGenerator();
        keyPairGenerator.init(new HIBEKeyPairGenerationParameter(pairingParameters, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String... ids) {
        if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof HIBEBBG05MasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBEBBG05MasterSecretKeySerParameter.class.getName());
        }
        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
        secretKeyGenerator.init(new HIBESecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String id) {
        if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBEBBG05SecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBEBBG05SecretKeySerParameter.class.getName());
        }
        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEDelegateGenerationParameter(
                publicKey, secretKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeySerParameter.class.getName());
        }
        HIBEBBG05EncryptionGenerator encryptionGenerator = new HIBEBBG05EncryptionGenerator();
        encryptionGenerator.init(new HIBEEncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids){
        if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeySerParameter.class.getName());
        }
        HIBEBBG05EncryptionGenerator encryptionGenerator = new HIBEBBG05EncryptionGenerator();
        encryptionGenerator.init(new HIBEEncryptionGenerationParameter(publicKey, ids, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBEBBG05SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBEBBG05SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof HIBEBBG05CiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBEBBG05CiphertextSerParameter.class.getName());
        }
        HIBEBBG05DecryptionGenerator decapsulationGenerator = new HIBEBBG05DecryptionGenerator();
        decapsulationGenerator.init(new HIBEDecryptionGenerationParameter(
                publicKey, secretKey, ids, ciphertext));
        return decapsulationGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBEBBG05SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBEBBG05SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof HIBEBBG05HeaderSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + header.getClass().getName() + ", require "
                            + HIBEBBG05HeaderSerParameter.class.getName());
        }
        HIBEBBG05DecryptionGenerator decapsulationGenerator = new HIBEBBG05DecryptionGenerator();
        decapsulationGenerator.init(new HIBEDecryptionGenerationParameter(
                publicKey, secretKey, ids, header));
        return decapsulationGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

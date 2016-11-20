package cn.edu.buaa.crypto.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05DecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams.*;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
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

    public AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxDepth) {
        HIBEBBG05KeyPairGenerator keyPairGenerator = new HIBEBBG05KeyPairGenerator();
        keyPairGenerator.init(new HIBEBBG05KeyPairGenerationParameter(pairingParameters, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String... ids) {
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
        secretKeyGenerator.init(new HIBEBBG05SecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public AsymmetricKeySerParameter delegate(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, String id) {
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
        secretKeyGenerator.init(new HIBEBBG05DelegateGenerationParameter(
                publicKey, secretKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(AsymmetricKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof HIBEBBG05PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeySerParameter.class.getName());
        }
        HIBEBBG05EncryptionGenerator encryptionGenerator = new HIBEBBG05EncryptionGenerator();
        encryptionGenerator.init(new HIBEBBG05EncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey,
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
        if (!(ciphertext instanceof HIBEBBG05CipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBEBBG05CipherSerParameter.class.getName());
        }
        HIBEBBG05DecapsulationGenerator decapsulationGenerator = new HIBEBBG05DecapsulationGenerator();
        decapsulationGenerator.init(new HIBEBBG05DecryptionGenerationParameter(
                publicKey, secretKey, ids, ciphertext));
        return decapsulationGenerator.recoverMessage();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

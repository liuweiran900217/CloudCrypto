package cn.edu.buaa.crypto.encryption.hibe.bb04;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.genparams.*;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Boneh-Boyen HIBE engine.
 */
public class HIBEBB04Engine implements HIBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Boneh-Boyen-04 HIBE scheme";

    private static HIBEBB04Engine engine;

    public static HIBEBB04Engine getInstance() {
        if (engine == null) {
            engine = new HIBEBB04Engine();
        }
        return engine;
    }

    private HIBEBB04Engine() {

    }

    public AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxDepth) {
        HIBEBB04KeyPairGenerator keyPairGenerator = new HIBEBB04KeyPairGenerator();
        keyPairGenerator.init(new HIBEBB04KeyPairGenerationParameter(pairingParameters, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String... ids) {
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBB04PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof HIBEBB04MasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBEBB04MasterSecretKeySerParameter.class.getName());
        }
        HIBEBB04SecretKeyGenerator secretKeyGenerator = new HIBEBB04SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEBB04SecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public AsymmetricKeySerParameter delegate(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, String id) {
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBB04PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBEBB04SecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBEBB04SecretKeySerParameter.class.getName());
        }
        HIBEBB04SecretKeyGenerator secretKeyGenerator = new HIBEBB04SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEBB04DelegateGenerationParameter(
                publicKey, secretKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(AsymmetricKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBB04PublicKeySerParameter.class.getName());
        }
        HIBEBB04EncryptionGenerator encryptionGenerator = new HIBEBB04EncryptionGenerator();
        encryptionGenerator.init(new HIBEBB04EncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey,
            String[] ids, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBB04PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBEBB04SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBEBB04SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof HIBEBB04CipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBEBB04CipherSerParameter.class.getName());
        }
        HIBEBB04DecryptionGenerator decryptionGenerator = new HIBEBB04DecryptionGenerator();
        decryptionGenerator.init(new HIBEBB04DecryptionGenerationParameter(publicKey, secretKey, ids, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

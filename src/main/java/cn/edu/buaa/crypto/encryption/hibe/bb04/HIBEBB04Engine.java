package cn.edu.buaa.crypto.encryption.hibe.bb04;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04DecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04EncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Engine for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04Engine implements HIBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "BB04HIBE";

    private static HIBEBB04Engine engine;

    public static HIBEBB04Engine getInstance() {
        if (engine == null) {
            engine = new HIBEBB04Engine();
        }
        return engine;
    }

    private HIBEBB04Engine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxDepth) {
        HIBEBB04KeyPairGenerator keyPairGenerator = new HIBEBB04KeyPairGenerator();
        keyPairGenerator.init(new HIBEBB04KeyPairGenerationParameters(rBitLength, qBitLength, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String... ids) {
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
        secretKeyGenerator.init(new HIBEBB04SecretKeyGenerationParameters(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, String id) {
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
        secretKeyGenerator.init(new HIBEBB04DelegateGenerationParameters(
                publicKey, secretKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(CipherParameters publicKey, String... ids){
        if (!(publicKey instanceof HIBEBB04PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBB04PublicKeySerParameter.class.getName());
        }
        HIBEBB04EncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBEBB04EncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBEBB04CiphertextGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] ids,
            CipherParameters ciphertext) throws InvalidCipherTextException {
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
        HIBEBB04DecapsulationGenerator keyDecapsulationGenerator = new HIBEBB04DecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBEBB04DecapsulationParameters(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

package cn.edu.buaa.crypto.encryption.hibe.bb04;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.*;
import cn.edu.buaa.crypto.algebra.params.PairingKeyEncapsulationPair;
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
        if (!(publicKey instanceof HIBEBB04PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBB04PublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof HIBEBB04MasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBEBB04MasterSecretKeyParameters.class.getName());
        }
        HIBEBB04SecretKeyGenerator secretKeyGenerator = new HIBEBB04SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEBB04SecretKeyGenerationParameters(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, String id) {
        if (!(publicKey instanceof HIBEBB04PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBB04PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBEBB04SecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBEBB04SecretKeyParameters.class.getName());
        }
        HIBEBB04SecretKeyGenerator secretKeyGenerator = new HIBEBB04SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEBB04DelegateGenerationParameters(
                publicKey, secretKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids){
        if (!(publicKey instanceof HIBEBB04PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBB04PublicKeyParameters.class.getName());
        }
        HIBEBB04KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBEBB04KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBEBB04CiphertextGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] ids,
            CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBEBB04PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBB04PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBEBB04SecretKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBEBB04SecretKeyParameters.class.getName());
        }
        if (!(ciphertext instanceof HIBEBB04CiphertextParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBEBB04CiphertextParameters.class.getName());
        }
        HIBEBB04KeyDecapsulationGenerator keyDecapsulationGenerator = new HIBEBB04KeyDecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBEBB04DecapsulationParameters(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

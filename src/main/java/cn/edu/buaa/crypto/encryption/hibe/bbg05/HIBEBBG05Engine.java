package cn.edu.buaa.crypto.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05KeyDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05KeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.*;
import cn.edu.buaa.crypto.algebra.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE engine.
 */
public class HIBEBBG05Engine implements HIBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "BBG05HIBE";

    private static HIBEBBG05Engine engine;

    public static HIBEBBG05Engine getInstance() {
        if (engine == null) {
            engine = new HIBEBBG05Engine();
        }
        return engine;
    }

    private HIBEBBG05Engine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxDepth) {
        HIBEBBG05KeyPairGenerator keyPairGenerator = new HIBEBBG05KeyPairGenerator();
        keyPairGenerator.init(new HIBEBBG05KeyPairGenerationParameters(rBitLength, qBitLength, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String... ids) {
        if (!(publicKey instanceof HIBEBBG05PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof HIBEBBG05MasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBEBBG05MasterSecretKeyParameters.class.getName());
        }
        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEBBG05SecretKeyGenerationParameters(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, String id) {
        if (!(publicKey instanceof HIBEBBG05PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBEBBG05SecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBEBBG05SecretKeyParameters.class.getName());
        }
        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEBBG05DelegateGenerationParameters(
                publicKey, secretKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids){
        if (!(publicKey instanceof HIBEBBG05PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeyParameters.class.getName());
        }
        HIBEBBG05KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBEBBG05KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBEBBG05CiphertextGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] ids,
            CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBEBBG05PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBEBBG05PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBEBBG05SecretKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBEBBG05SecretKeyParameters.class.getName());
        }
        if (!(ciphertext instanceof HIBEBBG05CiphertextParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBEBBG05CiphertextParameters.class.getName());
        }
        HIBEBBG05KeyDecapsulationGenerator keyDecapsulationGenerator = new HIBEBBG05KeyDecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBEBBG05DecapsulationParameters(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

package cn.edu.buaa.crypto.encryption.hibbe.llw16a;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aKeyDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aKeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.params.*;
import cn.edu.buaa.crypto.algebra.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE.
 */
public class HIBBELLW16Engine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW16HIBBE";

    private static HIBBELLW16Engine engine;

    public static HIBBELLW16Engine getInstance() {
        if (engine == null) {
            engine = new HIBBELLW16Engine();
        }
        return engine;
    }

    private HIBBELLW16Engine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxUser) {
        HIBBELLW16aKeyPairGenerator keyPairGenerator = new HIBBELLW16aKeyPairGenerator();
        keyPairGenerator.init(new HIBBELLW16aKeyPairGenerationParameters(rBitLength, qBitLength, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW16aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16aPublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW16aMasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBBELLW16aMasterSecretKeyParameters.class.getName());
        }
        HIBBELLW16aSecretKeyGenerator secretKeyGenerator = new HIBBELLW16aSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW16aSecretKeyGenerationParameters(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW16aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16aPublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16aSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBBELLW16aSecretKeyParameters.class.getName());
        }
        HIBBELLW16aSecretKeyGenerator secretKeyGenerator = new HIBBELLW16aSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW16aDelegateGenerationParameters(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids){
        if (!(publicKey instanceof HIBBELLW16aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16aPublicKeyParameters.class.getName());
        }
        HIBBELLW16aKeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBBELLW16aKeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBBELLW16aCiphertextGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] ids,
            CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW16aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16aPublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16aSecretKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBBELLW16aSecretKeyParameters.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW16aCiphertextParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW16aCiphertextParameters.class.getName());
        }
        HIBBELLW16aKeyDecapsulationGenerator keyDecapsulationGenerator = new HIBBELLW16aKeyDecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBBELLW16aDecapsulationParameters(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

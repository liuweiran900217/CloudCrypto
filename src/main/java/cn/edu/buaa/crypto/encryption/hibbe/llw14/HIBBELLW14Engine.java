package cn.edu.buaa.crypto.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14KeyDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14KeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.*;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW14Engine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW14HIBBE";

    public HIBBELLW14Engine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxUser) {
        HIBBELLW14KeyPairGenerator keyPairGenerator = new HIBBELLW14KeyPairGenerator();
        keyPairGenerator.init(new HIBBELLW14KeyPairGenerationParameters(qBitLength, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW14PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW14PublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW14MasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBBELLW14MasterSecretKeyParameters.class.getName());
        }
        HIBBELLW14SecretKeyGenerator secretKeyGenerator = new HIBBELLW14SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW14SecretKeyGenerationParameters(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW14PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW14PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW14SecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBBELLW14SecretKeyParameters.class.getName());
        }
        HIBBELLW14SecretKeyGenerator secretKeyGenerator = new HIBBELLW14SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW14DelegateGenerationParameters(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids){
        if (!(publicKey instanceof HIBBELLW14PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW14PublicKeyParameters.class.getName());
        }
        HIBBELLW14KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBBELLW14KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBBELLW14CiphertextGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] ids,
            CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW14PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW14PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW14SecretKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBBELLW14SecretKeyParameters.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW14CiphertextParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW14CiphertextParameters.class.getName());
        }
        HIBBELLW14KeyDecapsulationGenerator keyDecapsulationGenerator = new HIBBELLW14KeyDecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBBELLW14DecapsulationParameters(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

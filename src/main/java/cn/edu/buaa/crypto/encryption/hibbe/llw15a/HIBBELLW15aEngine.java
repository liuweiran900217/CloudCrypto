package cn.edu.buaa.crypto.encryption.hibbe.llw15a;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw15a.generators.HIBBELLW15aKeyDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw15a.generators.HIBBELLW15aKeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw15a.generators.HIBBELLW15aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw15a.generators.HIBBELLW15aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw15a.params.*;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW15aEngine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW15aHIBBE";

    public HIBBELLW15aEngine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxUser) {
        HIBBELLW15aKeyPairGenerator keyPairGenerator = new HIBBELLW15aKeyPairGenerator();
        keyPairGenerator.init(new HIBBELLW15aKeyPairGenerationParameters(qBitLength, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW15aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW15aPublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW15aMasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBBELLW15aMasterSecretKeyParameters.class.getName());
        }
        HIBBELLW15aSecretKeyGenerator secretKeyGenerator = new HIBBELLW15aSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW15aSecretKeyGenerationParameters(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW15aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW15aPublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW15aSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBBELLW15aSecretKeyParameters.class.getName());
        }
        HIBBELLW15aSecretKeyGenerator secretKeyGenerator = new HIBBELLW15aSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW15aDelegateGenerationParameters(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids){
        if (!(publicKey instanceof HIBBELLW15aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW15aPublicKeyParameters.class.getName());
        }
        HIBBELLW15aKeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBBELLW15aKeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBBELLW15aCiphertextGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] ids,
            CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW15aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW15aPublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW15aSecretKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBBELLW15aSecretKeyParameters.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW15aCiphertextParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW15aCiphertextParameters.class.getName());
        }
        HIBBELLW15aKeyDecapsulationGenerator keyDecapsulationGenerator = new HIBBELLW15aKeyDecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBBELLW15aDecapsulationParameters(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

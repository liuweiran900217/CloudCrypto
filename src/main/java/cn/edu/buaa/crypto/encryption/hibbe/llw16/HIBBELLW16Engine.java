package cn.edu.buaa.crypto.encryption.hibbe.llw16;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.generators.HIBBELLW16KeyDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.generators.HIBBELLW16KeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.generators.HIBBELLW16KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.generators.HIBBELLW16SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.*;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/17.
 */
public class HIBBELLW16Engine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW16HIBBE";

    public HIBBELLW16Engine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxUser) {
        HIBBELLW16KeyPairGenerator keyPairGenerator = new HIBBELLW16KeyPairGenerator();
        keyPairGenerator.init(new HIBBELLW16KeyPairGenerationParameters(rBitLength, qBitLength, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW16PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16PublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW16MasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBBELLW16MasterSecretKeyParameters.class.getName());
        }
        HIBBELLW16SecretKeyGenerator secretKeyGenerator = new HIBBELLW16SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW16SecretKeyGenerationParameters(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW16PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16SecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBBELLW16SecretKeyParameters.class.getName());
        }
        HIBBELLW16SecretKeyGenerator secretKeyGenerator = new HIBBELLW16SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW16DelegateGenerationParameters(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids){
        if (!(publicKey instanceof HIBBELLW16PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16PublicKeyParameters.class.getName());
        }
        HIBBELLW16KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBBELLW16KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBBELLW16CiphertextGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] ids,
            CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW16PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16SecretKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBBELLW16SecretKeyParameters.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW16CiphertextParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW16CiphertextParameters.class.getName());
        }
        HIBBELLW16KeyDecapsulationGenerator keyDecapsulationGenerator = new HIBBELLW16KeyDecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBBELLW16DecapsulationParameters(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

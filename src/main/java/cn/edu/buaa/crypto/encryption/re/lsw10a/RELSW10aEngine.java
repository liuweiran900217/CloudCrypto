package cn.edu.buaa.crypto.encryption.re.lsw10a;

import cn.edu.buaa.crypto.encryption.re.REEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10ADecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10AEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.*;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters Revocation Encryption engine.
 */
public class RELSW10aEngine implements REEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LSW10aRE";

    private static RELSW10aEngine engine;

    public static RELSW10aEngine getInstance() {
        if (engine == null) {
            engine = new RELSW10aEngine();
        }
        return engine;
    }

    private RELSW10aEngine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength) {
        RELSW10aKeyPairGenerator keyPairGenerator = new RELSW10aKeyPairGenerator();
        keyPairGenerator.init(new RELSW10aKeyPairGenerationParameters(rBitLength, qBitLength));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String id) {
        if (!(publicKey instanceof RELSW10APublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RELSW10APublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof RELSW10AMasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + RELSW10AMasterSecretKeySerParameter.class.getName());
        }
        RELSW10aSecretKeyGenerator secretKeyGenerator = new RELSW10aSecretKeyGenerator();
        secretKeyGenerator.init(new RELSW10aSecretKeyGenerationParameters(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(CipherParameters publicKey, String... ids){
        if (!(publicKey instanceof RELSW10APublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RELSW10APublicKeySerParameter.class.getName());
        }
        RELSW10AEncapsulationPairGenerator keyEncapsulationPairGenerator = new RELSW10AEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new RELSW10aCiphertextGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] ids,
            CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof RELSW10APublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RELSW10APublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RELSW10ASecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + RELSW10ASecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof RELSW10ACipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + RELSW10ACipherSerParameter.class.getName());
        }
        RELSW10ADecapsulationGenerator keyDecapsulationGenerator = new RELSW10ADecapsulationGenerator();
        keyDecapsulationGenerator.init(new RELSW10aDecapsulationParameters(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

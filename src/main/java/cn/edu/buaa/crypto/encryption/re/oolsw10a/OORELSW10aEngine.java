package cn.edu.buaa.crypto.encryption.re.oolsw10a;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.encryption.re.OOREEngine;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.generators.*;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.*;
import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/4/10.
 */
public class OORELSW10aEngine implements OOREEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "OOLSW10aRE";
    private CHEngine chEngine;

    public OORELSW10aEngine(CHEngine chEngine) {
        this.chEngine = chEngine;
    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength) {
        OORELSW10aKeyPairGenerator keyPairGenerator = new OORELSW10aKeyPairGenerator();
        keyPairGenerator.init(new OORELSW10aKeyPairGenerationParameters(rBitLength, qBitLength, chEngine));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String id) {
        if (!(publicKey instanceof OORELSW10aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + OORELSW10aPublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof OORELSW10aMasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + OORELSW10aMasterSecretKeyParameters.class.getName());
        }
        OORELSW10aSecretKeyGenerator secretKeyGenerator = new OORELSW10aSecretKeyGenerator();
        secretKeyGenerator.init(new OORELSW10aSecretKeyGenerationParameters(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair offlineEncapsulation(CipherParameters publicKey, int n) {
        if (!(publicKey instanceof OORELSW10aPublicKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + OORELSW10aPublicKeyParameters.class.getName());
        }
        OORELSW10aICiphertextGenerator iCiphertextGenerator = new OORELSW10aICiphertextGenerator();
        iCiphertextGenerator.init(new OORELSW10aICiphertextGenerationParameters(publicKey, n));
        return iCiphertextGenerator.generateEncryptionPair();
    }

    public PairingKeyEncapsulationPair onlineEncapsulation(CipherParameters publicKey, PairingCiphertextParameters iCiphertext, String... ids) {
        if (!(publicKey instanceof OORELSW10aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + OORELSW10aPublicKeyParameters.class.getName());
        }
        if (!(iCiphertext instanceof OORELSW10aICiphertextParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + OORELSW10aICiphertextParameters.class.getName());
        }
        OORELSW10aKeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new OORELSW10aKeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new OORELSW10aCiphertextGenerationParameters(publicKey, iCiphertext, ids));
        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids) {
        if (!(publicKey instanceof OORELSW10aPublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + OORELSW10aPublicKeyParameters.class.getName());
        }
        OORELSW10aKeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new OORELSW10aKeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new OORELSW10aCiphertextGenerationParameters(
                publicKey, ids));
        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation(CipherParameters publicKey, CipherParameters secretKey, String[] ids, CipherParameters ciphertext) throws InvalidCipherTextException {
            if (!(publicKey instanceof OORELSW10aPublicKeyParameters)){
                throw new IllegalArgumentException
                        ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                                + publicKey.getClass().getName() + ", require "
                                + OORELSW10aPublicKeyParameters.class.getName());
            }
            if (!(secretKey instanceof OORELSW10aSecretKeyParameters)){
                throw new IllegalArgumentException
                        ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                                + secretKey.getClass().getName() + ", require "
                                + OORELSW10aSecretKeyParameters.class.getName());
            }
            if (!(ciphertext instanceof OORELSW10aCiphertextParameters)){
                throw new IllegalArgumentException
                        ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                                + ciphertext.getClass().getName() + ", require "
                                + OORELSW10aCiphertextParameters.class.getName());
            }
            OORELSW10aKeyDecapsulationGenerator keyDecapsulationGenerator = new OORELSW10aKeyDecapsulationGenerator();
            keyDecapsulationGenerator.init(new OORELSW10aDecapsulationParameters(
                    publicKey, secretKey, ids, ciphertext));
            return keyDecapsulationGenerator.recoverKey();
    }
}

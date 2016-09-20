package cn.edu.buaa.crypto.encryption.ibbe.del07;

import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import cn.edu.buaa.crypto.encryption.ibbe.del07.generators.IBBEDel07KeyDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.ibbe.del07.generators.IBBEDel07KeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.ibbe.del07.generators.IBBEDel07KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.ibbe.del07.generators.IBBEDel07SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.*;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Engine for Delerablée IBBE scheme.
 */
public class IBBEDel07Engine implements IBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Del07-IBBE";

    private static IBBEDel07Engine engine;

    public static IBBEDel07Engine getInstance() {
        if (engine == null) {
            engine = new IBBEDel07Engine();
        }
        return engine;
    }

    private IBBEDel07Engine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxBroadcastReceiver) {
        IBBEDel07KeyPairGenerator keyPairGenerator = new IBBEDel07KeyPairGenerator();
        keyPairGenerator.init(new IBBEDel07KeyPairGenerationParameters(rBitLength, qBitLength, maxBroadcastReceiver));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String id) {
        if (!(publicKey instanceof IBBEDel07PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBBEDel07PublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof IBBEDel07MasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + IBBEDel07MasterSecretKeyParameters.class.getName());
        }
        IBBEDel07SecretKeyGenerator secretKeyGenerator = new IBBEDel07SecretKeyGenerator();
        secretKeyGenerator.init(new IBBEDel07SecretKeyGenerationParameters(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids) {
        if (!(publicKey instanceof IBBEDel07PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBBEDel07PublicKeyParameters.class.getName());
        }
        IBBEDel07KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new IBBEDel07KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new IBBEDel07CiphertextGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation(CipherParameters publicKey, CipherParameters secretKey, String[] ids, CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBBEDel07PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBBEDel07PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof IBBEDel07SecretKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + IBBEDel07SecretKeyParameters.class.getName());
        }
        if (!(ciphertext instanceof IBBEDel07CiphertextParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + IBBEDel07CiphertextParameters.class.getName());
        }
        IBBEDel07KeyDecapsulationGenerator keyDecapsulationGenerator = new IBBEDel07KeyDecapsulationGenerator();
        keyDecapsulationGenerator.init(new IBBEDel07DecapsulationParameters(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

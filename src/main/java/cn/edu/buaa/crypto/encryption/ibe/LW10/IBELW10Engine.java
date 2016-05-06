package cn.edu.buaa.crypto.encryption.ibe.LW10;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.LW10.generators.IBELW10KeyDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.ibe.LW10.generators.IBELW10KeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.LW10.generators.IBELW10KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.LW10.generators.IBELW10SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.ibe.LW10.params.*;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/6.
 */
public class IBELW10Engine implements IBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LW10IBE";

    public IBELW10Engine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength) {
        IBELW10KeyPairGenerator keyPairGenerator = new IBELW10KeyPairGenerator();
        keyPairGenerator.init(new IBELW10KeyPairGenerationParameters(qBitLength));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String id) {
        if (!(publicKey instanceof IBELW10PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBELW10PublicKeyParameters.class.getName());
        }
        if (!(masterKey instanceof IBELW10MasterSecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + IBELW10MasterSecretKeyParameters.class.getName());
        }
        IBELW10SecretKeyGenerator secretKeyGenerator = new IBELW10SecretKeyGenerator();
        secretKeyGenerator.init(new IBELW10SecretKeyGenerationParameters(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String id){
        if (!(publicKey instanceof IBELW10PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBELW10PublicKeyParameters.class.getName());
        }
        IBELW10KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new IBELW10KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new IBELW10CiphertextGenerationParameters(publicKey, id));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (CipherParameters publicKey, CipherParameters secretKey,
                                 String id, CipherParameters ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBELW10PublicKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBELW10PublicKeyParameters.class.getName());
        }
        if (!(secretKey instanceof IBELW10SecretKeyParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + IBELW10SecretKeyParameters.class.getName());
        }
        if (!(ciphertext instanceof IBELW10CiphertextParameters)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + IBELW10CiphertextParameters.class.getName());
        }
        IBELW10KeyDecapsulationGenerator keyDecapsulationGenerator = new IBELW10KeyDecapsulationGenerator();
        keyDecapsulationGenerator.init(new IBELW10DecapsulationParameters(
                publicKey, secretKey, id, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

package cn.edu.buaa.crypto.encryption.re.lsw10a;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.re.REEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.re.genparams.*;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aMasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters Revocation Encryption engine.
 */
public class RELSW10aEngine implements REEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Lewko-Waters-08a Revocation Encryption";

    private static RELSW10aEngine engine;

    public static RELSW10aEngine getInstance() {
        if (engine == null) {
            engine = new RELSW10aEngine();
        }
        return engine;
    }

    private RELSW10aEngine() {

    }

    public PairingKeySerPair setup(PairingParameters pairingParameters) {
        RELSW10aKeyPairGenerator keyPairGenerator = new RELSW10aKeyPairGenerator();
        keyPairGenerator.init(new REKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {
        if (!(publicKey instanceof RELSW10aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RELSW10aPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof RELSW10aMasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + RELSW10aMasterSecretKeySerParameter.class.getName());
        }
        RELSW10aSecretKeyGenerator secretKeyGenerator = new RELSW10aSecretKeyGenerator();
        secretKeyGenerator.init(new RESecretKeyGenerationParameter(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof RELSW10aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RELSW10aPublicKeySerParameter.class.getName());
        }
        RELSW10aEncryptionGenerator encryptionGenerator = new RELSW10aEncryptionGenerator();
        encryptionGenerator.init(new REEncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof RELSW10aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + RELSW10aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RELSW10aSecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + RELSW10aSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof RELSW10aCiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + RELSW10aCiphertextSerParameter.class.getName());
        }
        RELSW10aDecryptionGenerator decryptionGenerator = new RELSW10aDecryptionGenerator();
        decryptionGenerator.init(new REDecryptionGenerationParameter(
                publicKey, secretKey, ids, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

package cn.edu.buaa.crypto.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams.*;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu HIBBE engine published in 2014.
 */
public class HIBBELLW14Engine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Liu-Liu-Wu-14 CPA-secure composite-order HIBBE";

    private static HIBBELLW14Engine engine;

    public static HIBBELLW14Engine getInstance() {
        if (engine == null) {
            engine = new HIBBELLW14Engine();
        }
        return engine;
    }

    private HIBBELLW14Engine() {

    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
        HIBBELLW14KeyPairGenerator keyPairGenerator = new HIBBELLW14KeyPairGenerator();
        keyPairGenerator.init(new HIBBELLW14KeyPairGenerationParameter(pairingParameters, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW14PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW14MasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBBELLW14MasterSecretKeySerParameter.class.getName());
        }
        HIBBELLW14SecretKeyGenerator secretKeyGenerator = new HIBBELLW14SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW14SecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW14SecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBBELLW14SecretKeySerParameter.class.getName());
        }
        HIBBELLW14SecretKeyGenerator secretKeyGenerator = new HIBBELLW14SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW14DelegateGenerationParameter(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW14PublicKeySerParameter.class.getName());
        }
        HIBBELLW14EncryptionGenerator encryptionGenerator = new HIBBELLW14EncryptionGenerator();
        encryptionGenerator.init(new HIBBELLW14EncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption (PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW14SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBBELLW14SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW14CiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW14CiphertextSerParameter.class.getName());
        }
        HIBBELLW14DecryptionGenerator decryptionGenerator = new HIBBELLW14DecryptionGenerator();
        decryptionGenerator.init(new HIBBELLW14DecryptionGenerationParameter(publicKey, secretKey, ids, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

package cn.edu.buaa.crypto.encryption.hibbe.llw16a;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.*;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE.
 */
public class HIBBELLW16aEngine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Liu-Liu-Wu-16 CPA-secure prime-order HIBBE";

    private static HIBBELLW16aEngine engine;

    public static HIBBELLW16aEngine getInstance() {
        if (engine == null) {
            engine = new HIBBELLW16aEngine();
        }
        return engine;
    }

    private HIBBELLW16aEngine() {

    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
        HIBBELLW16aKeyPairGenerator keyPairGenerator = new HIBBELLW16aKeyPairGenerator();
        keyPairGenerator.init(new HIBBEKeyPairGenerationParameter(pairingParameters, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW16aMasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBBELLW16aMasterSecretKeySerParameter.class.getName());
        }
        HIBBELLW16aSecretKeyGenerator secretKeyGenerator = new HIBBELLW16aSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBESecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16aSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBBELLW16aSecretKeySerParameter.class.getName());
        }
        HIBBELLW16aSecretKeyGenerator secretKeyGenerator = new HIBBELLW16aSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBEDelegateGenerationParameter(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        HIBBELLW16aEncryptionGenerator encryptionGenerator = new HIBBELLW16aEncryptionGenerator();
        encryptionGenerator.init(new HIBBEEncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16aSecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBBELLW16aSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW16aCiphertextSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW16aCiphertextSerParameter.class.getName());
        }
        HIBBELLW16aDecryptionGenerator decryptionGenerator = new HIBBELLW16aDecryptionGenerator();
        decryptionGenerator.init(new HIBBEDecryptionGenerationParameter(
                publicKey, secretKey, ids, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

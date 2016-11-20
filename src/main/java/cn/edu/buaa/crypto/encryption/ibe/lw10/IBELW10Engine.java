package cn.edu.buaa.crypto.encryption.ibe.lw10;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.lw10.generators.IBELW10DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.lw10.generators.IBELW10EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.lw10.generators.IBELW10KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.lw10.generators.IBELW10SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10EncryptionGenerationParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10DecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10KeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10SecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Waters IBE engine.
 */
public class IBELW10Engine implements IBEEngine {
    //Scheme name, used for exceptions
    private static final String SCHEME_NAME = "Lewko-Waters-10 IBE scheme";

    private static IBELW10Engine engine;

    public static IBELW10Engine getInstance() {
        if (engine == null) {
            engine = new IBELW10Engine();
        }
        return engine;
    }

    private IBELW10Engine() {

    }

    public AsymmetricKeySerPair setup(PairingParameters pairingParameters) {
        IBELW10KeyPairGenerator keyPairGenerator = new IBELW10KeyPairGenerator();
        keyPairGenerator.init(new IBELW10KeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String id) {
        if (!(publicKey instanceof IBELW10PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBELW10PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof IBELW10MasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + IBELW10MasterSecretKeySerParameter.class.getName());
        }
        IBELW10SecretKeyGenerator secretKeyGenerator = new IBELW10SecretKeyGenerator();
        secretKeyGenerator.init(new IBELW10SecretKeyGenerationParameter(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(AsymmetricKeySerParameter publicKey, String id, Element message){
        if (!(publicKey instanceof IBELW10PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBELW10PublicKeySerParameter.class.getName());
        }
        IBELW10EncryptionGenerator encryptionGenerator = new IBELW10EncryptionGenerator();
        encryptionGenerator.init(new IBELW10EncryptionGenerationParameters(publicKey, id, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey,
                                 String id, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBELW10PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBELW10PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof IBELW10SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + IBELW10SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof IBELW10CipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + IBELW10CipherSerParameter.class.getName());
        }
        IBELW10DecryptionGenerator decryptionGenerator = new IBELW10DecryptionGenerator();
        decryptionGenerator.init(new IBELW10DecryptionGenerationParameter(
                publicKey, secretKey, id, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

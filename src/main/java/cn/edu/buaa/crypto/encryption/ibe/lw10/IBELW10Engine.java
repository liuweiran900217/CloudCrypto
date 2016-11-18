package cn.edu.buaa.crypto.encryption.ibe.lw10;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.lw10.generators.IBELW10DecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.ibe.lw10.generators.IBELW10EncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.lw10.generators.IBELW10KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.lw10.generators.IBELW10SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10CiphertextGenerationParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10DecapsulationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10KeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10SecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.*;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
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

    public PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String id){
        if (!(publicKey instanceof IBELW10PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + IBELW10PublicKeySerParameter.class.getName());
        }
        IBELW10EncapsulationPairGenerator keyEncapsulationPairGenerator = new IBELW10EncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new IBELW10CiphertextGenerationParameters(publicKey, id));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey,
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
        IBELW10DecapsulationGenerator keyDecapsulationGenerator = new IBELW10DecapsulationGenerator();
        keyDecapsulationGenerator.init(new IBELW10DecapsulationParameter(
                publicKey, secretKey, id, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

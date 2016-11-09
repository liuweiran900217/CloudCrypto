package cn.edu.buaa.crypto.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14DecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14EncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.generators.HIBBELLW14SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams.*;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.*;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu HIBBE engine published in 2014.
 */
public class HIBBELLW14Engine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW14HIBBE";

    private static HIBBELLW14Engine engine;

    public static HIBBELLW14Engine getInstance() {
        if (engine == null) {
            engine = new HIBBELLW14Engine();
        }
        return engine;
    }

    private HIBBELLW14Engine() {

    }

    public AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
        HIBBELLW14KeyPairGenerator keyPairGenerator = new HIBBELLW14KeyPairGenerator();
        keyPairGenerator.init(new HIBBELLW14KeyPairGenerationParameter(pairingParameters, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String[] ids) {
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

    public AsymmetricKeySerParameter delegate(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, int index, String id) {
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

    public PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String... ids){
        if (!(publicKey instanceof HIBBELLW14PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW14PublicKeySerParameter.class.getName());
        }
        HIBBELLW14EncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBBELLW14EncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBBELLW14CiphertextGenerationParameter(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, String[] ids, CipherParameters ciphertext)
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
        if (!(ciphertext instanceof HIBBELLW14CipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW14CipherSerParameter.class.getName());
        }
        HIBBELLW14DecapsulationGenerator keyDecapsulationGenerator = new HIBBELLW14DecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBBELLW14DecapsulationParameter(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

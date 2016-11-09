package cn.edu.buaa.crypto.encryption.hibbe.llw16a;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators.HIBBELLW16aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams.*;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.*;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE.
 */
public class HIBBELLW16aEngine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW16HIBBE";

    private static HIBBELLW16aEngine engine;

    public static HIBBELLW16aEngine getInstance() {
        if (engine == null) {
            engine = new HIBBELLW16aEngine();
        }
        return engine;
    }

    private HIBBELLW16aEngine() {

    }

    public AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
        HIBBELLW16aKeyPairGenerator keyPairGenerator = new HIBBELLW16aKeyPairGenerator();
        keyPairGenerator.init(new HIBBELLW16aKeyPairGenerationParameter(pairingParameters, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String[] ids) {
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
        secretKeyGenerator.init(new HIBBELLW16aSecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public AsymmetricKeySerParameter delegate(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, int index, String id) {
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
        secretKeyGenerator.init(new HIBBELLW16aDelegateGenerationParameter(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String... ids){
        if (!(publicKey instanceof HIBBELLW16aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16aPublicKeySerParameter.class.getName());
        }
        HIBBELLW16aEncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBBELLW16aEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBBELLW16aCiphertextGenerationParameter(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, String[] ids, CipherParameters ciphertext)
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
        if (!(ciphertext instanceof HIBBELLW16ACipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW16ACipherSerParameter.class.getName());
        }
        HIBBELLW16aDecapsulationGenerator keyDecapsulationGenerator = new HIBBELLW16aDecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBBELLW16aDecapsulationParameter(
                publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

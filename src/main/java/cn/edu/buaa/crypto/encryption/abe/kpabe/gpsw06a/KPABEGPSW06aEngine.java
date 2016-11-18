package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators.KPABEGPSW06aDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators.KPABEGPSW06aEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators.KPABEGPSW06aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators.KPABEGPSW06aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams.KPABEGPSW06aCiphertextGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams.KPABEGPSW06aDecapsulationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams.KPABEGPSW06aKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams.KPABEGPSW06aSecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE engine.
 */
public class KPABEGPSW06aEngine extends KPABEEngine {
    //Scheme name, used for exceptions
    private static final String SCHEME_NAME = "Goyal-Pandey-Sahai-Waters-06 small-universe KP-ABE";

    private static KPABEGPSW06aEngine engine;

    public static KPABEGPSW06aEngine getInstance() {
        if (engine == null) {
            engine = new KPABEGPSW06aEngine();
        }
        return engine;
    }

    private KPABEGPSW06aEngine() {

    }

    public String getEngineName() {
        return SCHEME_NAME;
    }

    public AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        KPABEGPSW06aKeyPairGenerator keyPairGenerator = new KPABEGPSW06aKeyPairGenerator();
        keyPairGenerator.init(new KPABEGPSW06aKeyPairGenerationParameter(pairingParameters, maxAttributesNum));

        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof KPABEGPSW06aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEGPSW06aPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof KPABEGPSW06aMasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + KPABEGPSW06aMasterSecretKeySerParameter.class.getName());
        }
        KPABEGPSW06aSecretKeyGenerator secretKeyGenerator = new KPABEGPSW06aSecretKeyGenerator();
        secretKeyGenerator.init(new KPABEGPSW06aSecretKeyGenerationParameter(
                accessControlEngine, publicKey, masterKey, accessPolicyIntArrays, rhos));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String[] attributes) {
        if (!(publicKey instanceof KPABEGPSW06aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEGPSW06aPublicKeySerParameter.class.getName());
        }
        KPABEGPSW06aEncapsulationPairGenerator keyEncapsulationPairGenerator = new KPABEGPSW06aEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new KPABEGPSW06aCiphertextGenerationParameter(
                publicKey, attributes));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey,
                                String[] attributes, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABEGPSW06aPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + KPABEGPSW06aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABEGPSW06aSecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + KPABEGPSW06aSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof KPABEGPSW06aCipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + KPABEGPSW06aCipherSerParameter.class.getName());
        }
        KPABEGPSW06aDecapsulationGenerator keyDecapsulationGenerator = new KPABEGPSW06aDecapsulationGenerator();
        keyDecapsulationGenerator.init(new KPABEGPSW06aDecapsulationParameter(
                accessControlEngine, publicKey, secretKey, attributes, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

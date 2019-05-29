package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators.KPABEGPSW06aDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators.KPABEGPSW06aEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators.KPABEGPSW06aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators.KPABEGPSW06aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE engine.
 */
public class KPABEGPSW06aEngine extends KPABEEngine {
    private static final String SCHEME_NAME = "Goyal-Pandey-Sahai-Waters-06 small-universe KP-ABE";

    private static KPABEGPSW06aEngine engine;

    public static KPABEGPSW06aEngine getInstance() {
        if (engine == null) {
            engine = new KPABEGPSW06aEngine();
        }
        return engine;
    }

    private KPABEGPSW06aEngine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        KPABEGPSW06aKeyPairGenerator keyPairGenerator = new KPABEGPSW06aKeyPairGenerator();
        keyPairGenerator.init(new KPABEKeyPairGenerationParameter(pairingParameters, maxAttributesNum));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof KPABEGPSW06aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06aPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof KPABEGPSW06aMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, KPABEGPSW06aMasterSecretKeySerParameter.class.getName());
        }
        KPABEGPSW06aSecretKeyGenerator secretKeyGenerator = new KPABEGPSW06aSecretKeyGenerator();
        secretKeyGenerator.init(new KPABESecretKeyGenerationParameter(
                accessControlEngine, publicKey, masterKey, accessPolicyIntArrays, rhos));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] attributes, Element message) {
        if (!(publicKey instanceof KPABEGPSW06aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06aPublicKeySerParameter.class.getName());
        }
        KPABEGPSW06aEncryptionGenerator encryptionGenerator = new KPABEGPSW06aEncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] attributes) {
        if (!(publicKey instanceof KPABEGPSW06aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06aPublicKeySerParameter.class.getName());
        }
        KPABEGPSW06aEncryptionGenerator encryptionGenerator = new KPABEGPSW06aEncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] attributes, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABEGPSW06aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABEGPSW06aSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, KPABEGPSW06aSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof KPABEGPSW06aCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, KPABEGPSW06aCiphertextSerParameter.class.getName());
        }
        KPABEGPSW06aDecryptionGenerator decryptionGenerator = new KPABEGPSW06aDecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String[] attributes, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABEGPSW06aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABEGPSW06aSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, KPABEGPSW06aSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof KPABEGPSW06aHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, KPABEGPSW06aHeaderSerParameter.class.getName());
        }
        KPABEGPSW06aDecryptionGenerator decryptionGenerator = new KPABEGPSW06aDecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, header));
        return decryptionGenerator.recoverKey();
    }
}

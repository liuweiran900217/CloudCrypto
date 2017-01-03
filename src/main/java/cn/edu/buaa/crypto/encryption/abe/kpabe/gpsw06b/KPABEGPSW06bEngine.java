package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators.KPABEGPSW06bDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators.KPABEGPSW06bEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators.KPABEGPSW06bKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators.KPABEGPSW06bSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles engine.
 */
public class KPABEGPSW06bEngine extends KPABEEngine {
    private static final String SCHEME_NAME = "Goyal-Pandey-Sahai-Waters-06 large-universe KP-ABE";

    private static KPABEGPSW06bEngine engine;

    public static KPABEGPSW06bEngine getInstance() {
        if (engine == null) {
            engine = new KPABEGPSW06bEngine();
        }
        return engine;
    }

    private KPABEGPSW06bEngine() {
        super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        KPABEGPSW06bKeyPairGenerator keyPairGenerator = new KPABEGPSW06bKeyPairGenerator();
        keyPairGenerator.init(new KPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof KPABEGPSW06bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06bPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof KPABEGPSW06bMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, KPABEGPSW06bMasterSecretKeySerParameter.class.getName());
        }
        KPABEGPSW06bSecretKeyGenerator secretKeyGenerator = new KPABEGPSW06bSecretKeyGenerator();
        secretKeyGenerator.init(new KPABESecretKeyGenerationParameter(
                accessControlEngine, publicKey, masterKey, accessPolicyIntArrays, rhos));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] attributes, Element message) {
        if (!(publicKey instanceof KPABEGPSW06bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06bPublicKeySerParameter.class.getName());
        }
        KPABEGPSW06bEncryptionGenerator encryptionGenerator = new KPABEGPSW06bEncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] attributes) {
        if (!(publicKey instanceof KPABEGPSW06bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06bPublicKeySerParameter.class.getName());
        }
        KPABEGPSW06bEncryptionGenerator encryptionGenerator = new KPABEGPSW06bEncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABEGPSW06bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABEGPSW06bSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, KPABEGPSW06bSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof KPABEGPSW06bCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, KPABEGPSW06bCiphertextSerParameter.class.getName());
        }
        KPABEGPSW06bDecryptionGenerator decryptionGenerator = new KPABEGPSW06bDecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABEGPSW06bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABEGPSW06bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABEGPSW06bSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, KPABEGPSW06bSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof KPABEGPSW06bHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, KPABEGPSW06bHeaderSerParameter.class.getName());
        }
        KPABEGPSW06bDecryptionGenerator decryptionGenerator = new KPABEGPSW06bDecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, header));
        return decryptionGenerator.recoverKey();
    }
}

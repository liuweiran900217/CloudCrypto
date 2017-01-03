package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.OOCPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.*;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators.*;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE engine.
 */
public class OOCPABEHW14Engine extends OOCPABEEngine {
    private static final String SCHEME_NAME = "Hohenberger-Waters-14 CPA-secure large-universe OO-CP-ABE";
    private static OOCPABEHW14Engine engine;

    public static OOCPABEHW14Engine getInstance() {
        if (engine == null) {
            engine = new OOCPABEHW14Engine();
        }
        return engine;
    }

    private OOCPABEHW14Engine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        CPABEHW14KeyPairGenerator keyPairGenerator = new CPABEHW14KeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof CPABEHW14PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof CPABEHW14MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, CPABEHW14MasterSecretKeySerParameter.class.getName());
        }
        CPABEHW14SecretKeyGenerator secretKeyGenerator = new CPABEHW14SecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof CPABEHW14PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEHW14PublicKeySerParameter.class.getName());
        }
        CPABEHW14EncryptionGenerator encryptionGenerator = new CPABEHW14EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof CPABEHW14PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEHW14PublicKeySerParameter.class.getName());
        }
        CPABEHW14EncryptionGenerator encryptionGenerator = new CPABEHW14EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABEHW14PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABEHW14SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABEHW14SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof CPABEHW14CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, CPABEHW14CiphertextSerParameter.class.getName());
        }
        CPABEHW14DecryptionGenerator decryptionGenerator = new CPABEHW14DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABEHW14PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABEHW14SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABEHW14SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof CPABEHW14HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, CPABEHW14HeaderSerParameter.class.getName());
        }
        CPABEHW14DecryptionGenerator decryptionGenerator = new CPABEHW14DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header));
        return decryptionGenerator.recoverKey();
    }

    public PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n) {
        if (!(publicKey instanceof CPABEHW14PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEHW14PublicKeySerParameter.class.getName());
        }
        CPABEHW14IntermediateGenerator intermediateGenerator = new CPABEHW14IntermediateGenerator();
        intermediateGenerator.init(new CPABEIntermediateGenerationParameter(
                publicKey, n));

        return intermediateGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
            int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof CPABEHW14PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof CPABEHW14IntermediateSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, CPABEHW14IntermediateSerParameter.class.getName());
        }
        CPABEHW14EncryptionGenerator encryptionGenerator = new CPABEHW14EncryptionGenerator();
        CPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new CPABEEncryptionGenerationParameter(accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);

        return encryptionGenerator.generateEncryptionPair();
    }

    public PairingCipherSerParameter encryption(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
            int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof CPABEHW14PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEHW14PublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof CPABEHW14IntermediateSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, CPABEHW14IntermediateSerParameter.class.getName());
        }
        CPABEHW14EncryptionGenerator encryptionGenerator = new CPABEHW14EncryptionGenerator();
        CPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new CPABEEncryptionGenerationParameter(accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);

        return encryptionGenerator.generateCiphertext();
    }
}

package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.CPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.generators.CPABEBSW07DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.generators.CPABEBSW07EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.generators.CPABEBSW07KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.generators.CPABEBSW07SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.*;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE engine.
 */
public class CPABEBSW07Engine extends CPABEEngine {
    private static final String SCHEME_NAME = "Bethencourt-Sahai-Waters large-universe CP-ABE";

    private static CPABEBSW07Engine engine;

    public static CPABEBSW07Engine getInstance() {
        if (engine == null) {
            engine = new CPABEBSW07Engine();
        }
        return engine;
    }

    private CPABEBSW07Engine() {
        super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        CPABEBSW07KeyPairGenerator keyPairGenerator = new CPABEBSW07KeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof CPABEBSW07PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEBSW07PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof CPABEBSW07MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, CPABEBSW07MasterSecretKeySerParameter.class.getName());
        }
        CPABEBSW07SecretKeyGenerator secretKeyGenerator = new CPABEBSW07SecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof CPABEBSW07PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEBSW07PublicKeySerParameter.class.getName());
        }
        CPABEBSW07EncryptionGenerator encryptionGenerator = new CPABEBSW07EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof CPABEBSW07PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEBSW07PublicKeySerParameter.class.getName());
        }
        CPABEBSW07EncryptionGenerator encryptionGenerator = new CPABEBSW07EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABEBSW07PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEBSW07PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABEBSW07SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABEBSW07SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof CPABEBSW07CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, CPABEBSW07CiphertextSerParameter.class.getName());
        }
        CPABEBSW07DecryptionGenerator decryptionGenerator = new CPABEBSW07DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABEBSW07PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABEBSW07PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABEBSW07SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABEBSW07SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof CPABEBSW07HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, CPABEBSW07HeaderSerParameter.class.getName());
        }
        CPABEBSW07DecryptionGenerator decryptionGenerator = new CPABEBSW07DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header));
        return decryptionGenerator.recoverKey();
    }
}

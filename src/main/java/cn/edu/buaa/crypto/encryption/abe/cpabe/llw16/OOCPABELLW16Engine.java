package cn.edu.buaa.crypto.encryption.abe.cpabe.llw16;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.*;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.OOCPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.*;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.generators.*;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-CP-ABE engine.
 */
public class OOCPABELLW16Engine extends OOCPABEEngine {
    private static final String SCHEME_NAME = "Liu-Liu-Wu-16 CCA2-secure large-universe OO-CP-ABE";
    private static OOCPABELLW16Engine engine;
    private ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bHasher(), new SHA256Digest());
    private AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
    private KeyGenerationParameters chKeyPairGenerationParameter
            = new DLogKR00bKeyGenerationParameters(new SecureRandom(), SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);

    public static OOCPABELLW16Engine getInstance() {
        if (engine == null) {
            engine = new OOCPABELLW16Engine();
        }
        return engine;
    }

    private OOCPABELLW16Engine() {
        super(SCHEME_NAME, Engine.ProveSecModel.Standard, Engine.PayloadSecLevel.CCA2, Engine.PredicateSecLevel.NON_ANON);
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher,
                                   AsymmetricKeySerPairGenerator chKeyPairGenerator,
                                   KeyGenerationParameters keyGenerationParameters) {
        this.chameleonHasher = chameleonHasher;
        this.chKeyPairGenerator = chKeyPairGenerator;
        this.chKeyPairGenerationParameter = keyGenerationParameters;
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        CPABELLW16KeyPairGenerator keyPairGenerator = new CPABELLW16KeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(
                pairingParameters, this.chKeyPairGenerator, this.chKeyPairGenerationParameter));
        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof CPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof CPABELLW16MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, CPABELLW16MasterSecretKeySerParameter.class.getName());
        }
        CPABELLW16SecretKeyGenerator secretKeyGenerator = new CPABELLW16SecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));
        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof CPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABELLW16PublicKeySerParameter.class.getName());
        }
        CPABELLW16EncryptionGenerator encryptionGenerator = new CPABELLW16EncryptionGenerator();
        CPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new CPABEEncryptionGenerationParameter(accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerator(this.chKeyPairGenerator);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerationParameter(this.chKeyPairGenerationParameter);
        encryptionGenerator.init(encryptionGenerationParameter);

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof CPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABELLW16PublicKeySerParameter.class.getName());
        }
        CPABELLW16EncryptionGenerator encryptionGenerator = new CPABELLW16EncryptionGenerator();
        CPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new CPABEEncryptionGenerationParameter(accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerator(this.chKeyPairGenerator);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerationParameter(this.chKeyPairGenerationParameter);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABELLW16SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABELLW16SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof CPABELLW16CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, CPABELLW16CiphertextSerParameter.class.getName());
        }
        CPABELLW16DecryptionGenerator decryptionGenerator = new CPABELLW16DecryptionGenerator();
        CPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABELLW16SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABELLW16SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof CPABELLW16HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, CPABELLW16HeaderSerParameter.class.getName());
        }
        CPABELLW16DecryptionGenerator decryptionGenerator = new CPABELLW16DecryptionGenerator();
        CPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverKey();
    }

    public PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n) {
        if (!(publicKey instanceof CPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABELLW16PublicKeySerParameter.class.getName());
        }
        CPABELLW16IntermediateGenerator intermediateGenerator = new CPABELLW16IntermediateGenerator();
        CPABEIntermediateGenerationParameter intermediateGenerationParameter
                = new CPABEIntermediateGenerationParameter(publicKey, n);
        intermediateGenerationParameter.setChameleonHasher(this.chameleonHasher);
        intermediateGenerationParameter.setChameleonHashKeyPairGenerator(this.chKeyPairGenerator);
        intermediateGenerationParameter.setChameleonHashKeyGenerationParameter(this.chKeyPairGenerationParameter);
        intermediateGenerator.init(intermediateGenerationParameter);
        return intermediateGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
            int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof CPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof CPABELLW16IntermediateSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, CPABELLW16IntermediateSerParameter.class.getName());
        }
        CPABELLW16EncryptionGenerator encryptionGenerator = new CPABELLW16EncryptionGenerator();
        CPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new CPABEEncryptionGenerationParameter(accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);

        return encryptionGenerator.generateEncryptionPair();
    }

    public PairingCipherSerParameter encryption(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
            int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof CPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof CPABELLW16IntermediateSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, CPABELLW16IntermediateSerParameter.class.getName());
        }
        CPABELLW16EncryptionGenerator encryptionGenerator = new CPABELLW16EncryptionGenerator();
        CPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new CPABEEncryptionGenerationParameter(accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);

        return encryptionGenerator.generateCiphertext();
    }
}

package cn.edu.buaa.crypto.encryption.abe.kpabe.llw16;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.*;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bUniversalHasher;
import cn.edu.buaa.crypto.encryption.abe.kpabe.OOKPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.*;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.generators.*;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2017/1/3.
 *
 * Liu-Liu-Wu-16 CCA2-secure KP-ABE engine.
 */
public class OOKPABELLW16Engine extends OOKPABEEngine {
    private static final String SCHEME_NAME = "Liu-Liu-Wu-16 CCA2-secure large-universe OO-KP-ABE";

    private static OOKPABELLW16Engine engine;
    private ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bUniversalHasher(new SHA256Digest()), new SHA256Digest());
    private AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
    private KeyGenerationParameters chKeyPairGenerationParameter
            = new DLogKR00bKeyGenerationParameters(new SecureRandom(), SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);

    public static OOKPABELLW16Engine getInstance() {
        if (engine == null) {
            engine = new OOKPABELLW16Engine();
        }
        return engine;
    }

    private OOKPABELLW16Engine() {
        super(SCHEME_NAME, Engine.ProveSecModel.Standard, Engine.PayloadSecLevel.CCA2, Engine.PredicateSecLevel.NON_ANON);
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher,
                                   AsymmetricKeySerPairGenerator chKeyPairGenerator,
                                   KeyGenerationParameters keyGenerationParameter) {
        this.chameleonHasher = chameleonHasher;
        this.chKeyPairGenerator = chKeyPairGenerator;
        this.chKeyPairGenerationParameter = keyGenerationParameter;
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        KPABELLW16KeyPairGenerator keyPairGenerator = new KPABELLW16KeyPairGenerator();
        keyPairGenerator.init(new KPABEKeyPairGenerationParameter(pairingParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof KPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof KPABELLW16MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, KPABELLW16MasterSecretKeySerParameter.class.getName());
        }
        KPABELLW16SecretKeyGenerator secretKeyGenerator = new KPABELLW16SecretKeyGenerator();
        secretKeyGenerator.init(new KPABESecretKeyGenerationParameter(
                accessControlEngine, publicKey, masterKey, accessPolicyIntArrays, rhos));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] attributes, Element message) {
        if (!(publicKey instanceof KPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABELLW16PublicKeySerParameter.class.getName());
        }
        KPABELLW16EncryptionGenerator encryptionGenerator = new KPABELLW16EncryptionGenerator();
        KPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new KPABEEncryptionGenerationParameter(publicKey, attributes, message);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerator(this.chKeyPairGenerator);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerationParameter(this.chKeyPairGenerationParameter);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] attributes) {
        if (!(publicKey instanceof KPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABELLW16PublicKeySerParameter.class.getName());
        }
        KPABELLW16EncryptionGenerator encryptionGenerator = new KPABELLW16EncryptionGenerator();
        KPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new KPABEEncryptionGenerationParameter(publicKey, attributes, null);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerator(this.chKeyPairGenerator);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerationParameter(this.chKeyPairGenerationParameter);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABELLW16SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, KPABELLW16SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof KPABELLW16CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, KPABELLW16CiphertextSerParameter.class.getName());
        }
        KPABELLW16DecryptionGenerator decryptionGenerator = new KPABELLW16DecryptionGenerator();
        KPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new KPABEDecryptionGenerationParameter(accessControlEngine, publicKey, secretKey, attributes, ciphertext);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] attributes,
            PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof KPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof KPABELLW16SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, KPABELLW16SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof KPABELLW16HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, KPABELLW16HeaderSerParameter.class.getName());
        }
        KPABELLW16DecryptionGenerator decryptionGenerator = new KPABELLW16DecryptionGenerator();
        KPABEDecryptionGenerationParameter decryptionGenerationParameter
                = new KPABEDecryptionGenerationParameter(accessControlEngine, publicKey, secretKey, attributes, header);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverKey();
    }

    public PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n) {
        if (!(publicKey instanceof KPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABELLW16PublicKeySerParameter.class.getName());
        }
        KPABELLW16IntermediateGenerator intermediateGenerator = new KPABELLW16IntermediateGenerator();
        KPABEIntermediateGenerationParameter intermediateGenerationParameter
                = new KPABEIntermediateGenerationParameter(publicKey, n);
        intermediateGenerationParameter.setChameleonHasher(this.chameleonHasher);
        intermediateGenerationParameter.setChameleonHashKeyPairGenerator(this.chKeyPairGenerator);
        intermediateGenerationParameter.setChameleonHashKeyGenerationParameter(this.chKeyPairGenerationParameter);
        intermediateGenerator.init(intermediateGenerationParameter);
        return intermediateGenerator.generateCiphertext();
    }

    public PairingCipherSerParameter encryption(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] attributes, Element message) {
        if (!(publicKey instanceof KPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof KPABELLW16IntermediateSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, KPABELLW16IntermediateSerParameter.class.getName());
        }
        KPABELLW16EncryptionGenerator encryptionGenerator = new KPABELLW16EncryptionGenerator();
        KPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new KPABEEncryptionGenerationParameter(publicKey, attributes, message);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] attributes) {
        if (!(publicKey instanceof KPABELLW16PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, KPABELLW16PublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof KPABELLW16IntermediateSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, KPABELLW16IntermediateSerParameter.class.getName());
        }
        KPABELLW16EncryptionGenerator encryptionGenerator = new KPABELLW16EncryptionGenerator();
        KPABEEncryptionGenerationParameter encryptionGenerationParameter
                = new KPABEEncryptionGenerationParameter(publicKey, attributes, null);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateEncryptionPair();
    }
}

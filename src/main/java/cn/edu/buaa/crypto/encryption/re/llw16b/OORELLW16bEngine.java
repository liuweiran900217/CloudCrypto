package cn.edu.buaa.crypto.encryption.re.llw16b;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.*;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bUniversalHasher;
import cn.edu.buaa.crypto.encryption.re.OOREEngine;
import cn.edu.buaa.crypto.encryption.re.genparams.*;
import cn.edu.buaa.crypto.encryption.re.llw16b.generators.*;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE engine.
 */
public class OORELLW16bEngine extends OOREEngine {
    private static final String SCHEME_NAME = "Liu-Liu-Wu-16 CCA2-secure Revocation Encryption";
    private static OORELLW16bEngine engine;
    private ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bUniversalHasher(new SHA256Digest()), new SHA256Digest());
    private AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
    private KeyGenerationParameters chKeyPairGenerationParameter
            = new DLogKR00bKeyGenerationParameters(new SecureRandom(), SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);

    public static OORELLW16bEngine getInstance() {
        if (engine == null) {
            engine = new OORELLW16bEngine();
        }
        return engine;
    }

    private OORELLW16bEngine() {
        super(SCHEME_NAME, Engine.ProveSecModel.Standard, Engine.PayloadSecLevel.CCA2, Engine.PredicateSecLevel.NON_ANON);
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher,
                                   AsymmetricKeySerPairGenerator chKeyPairGenerator,
                                   KeyGenerationParameters keyGenerationParameter) {
        this.chameleonHasher = chameleonHasher;
        this.chKeyPairGenerator = chKeyPairGenerator;
        this.chKeyPairGenerationParameter = keyGenerationParameter;
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters) {
        RELLW16bKeyPairGenerator keyPairGenerator = new RELLW16bKeyPairGenerator();
        keyPairGenerator.init(new REKeyPairGenerationParameter(pairingParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {
        if (!(publicKey instanceof RELLW16bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16bPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof RELLW16bMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, RELLW16bMasterSecretKeySerParameter.class.getName());
        }
        RELLW16bSecretKeyGenerator secretKeyGenerator = new RELLW16bSecretKeyGenerator();
        secretKeyGenerator.init(new RESecretKeyGenerationParameter(
                publicKey, masterKey, id));
        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof RELLW16bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16bPublicKeySerParameter.class.getName());
        }
        RELLW16bEncryptionGenerator encryptionGenerator = new RELLW16bEncryptionGenerator();
        REEncryptionGenerationParameter encryptionGenerationParameter
                = new REEncryptionGenerationParameter(publicKey, ids, message);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerator(this.chKeyPairGenerator);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerationParameter(this.chKeyPairGenerationParameter);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
        if (!(publicKey instanceof RELLW16bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16bPublicKeySerParameter.class.getName());
        }
        RELLW16bEncryptionGenerator encryptionGenerator = new RELLW16bEncryptionGenerator();
        REEncryptionGenerationParameter encryptionGenerationParameter
                = new REEncryptionGenerationParameter(publicKey, ids, null);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerator(this.chKeyPairGenerator);
        encryptionGenerationParameter.setChameleonHashKeyPairGenerationParameter(this.chKeyPairGenerationParameter);
        encryptionGenerator.init(encryptionGenerationParameter);

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof RELLW16bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RELLW16bSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RELLW16bSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof RELLW16bCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, RELLW16bCiphertextSerParameter.class.getName());
        }
        RELLW16bDecryptionGenerator decryptionGenerator = new RELLW16bDecryptionGenerator();
        REDecryptionGenerationParameter decryptionGenerationParameter
                = new REDecryptionGenerationParameter(publicKey, secretKey, ids, ciphertext);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String[] ids, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof RELLW16bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RELLW16bSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RELLW16bSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof RELLW16bHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, RELLW16bHeaderSerParameter.class.getName());
        }
        RELLW16bDecryptionGenerator decryptionGenerator = new RELLW16bDecryptionGenerator();
        REDecryptionGenerationParameter decryptionGenerationParameter
                = new REDecryptionGenerationParameter(publicKey, secretKey, ids, header);
        decryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        decryptionGenerator.init(decryptionGenerationParameter);
        return decryptionGenerator.recoverKey();
    }

    public PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n) {
        if (!(publicKey instanceof RELLW16bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16bPublicKeySerParameter.class.getName());
        }
        RELLW16bIntermediateGenerator intermediateGenerator = new RELLW16bIntermediateGenerator();
        REIntermediateGenerationParameter intermediateGenerationParameter
                = new REIntermediateGenerationParameter(publicKey, n);
        intermediateGenerationParameter.setChameleonHasher(this.chameleonHasher);
        intermediateGenerationParameter.setChameleonHashKeyPairGenerator(this.chKeyPairGenerator);
        intermediateGenerationParameter.setChameleonHashKeyGenerationParameter(this.chKeyPairGenerationParameter);
        intermediateGenerator.init(intermediateGenerationParameter);
        return intermediateGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] ids) {
        if (!(publicKey instanceof RELLW16bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16bPublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof RELLW16bIntermediateSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, RELLW16bIntermediateSerParameter.class.getName());
        }
        RELLW16bEncryptionGenerator encryptionGenerator = new RELLW16bEncryptionGenerator();

        REEncryptionGenerationParameter encryptionGenerationParameter
                = new REEncryptionGenerationParameter(publicKey, ids, null);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateEncryptionPair();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] ids, Element message) {
        if (!(publicKey instanceof RELLW16bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16bPublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof RELLW16bIntermediateSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, RELLW16bIntermediateSerParameter.class.getName());
        }
        RELLW16bEncryptionGenerator encryptionGenerator = new RELLW16bEncryptionGenerator();
        REEncryptionGenerationParameter encryptionGenerationParameter
                = new REEncryptionGenerationParameter(publicKey, ids, message);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerationParameter.setChameleonHasher(this.chameleonHasher);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateCiphertext();
    }
}

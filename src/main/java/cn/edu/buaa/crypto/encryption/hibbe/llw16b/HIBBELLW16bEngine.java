package cn.edu.buaa.crypto.encryption.hibbe.llw16b;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.generators.HIBBELLW16bDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.generators.HIBBELLW16bEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.generators.HIBBELLW16bKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.generators.HIBBELLW16bSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams.*;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bSecretKeySerParameter;
import cn.edu.buaa.crypto.signature.pks.PairingDigestSigner;
import cn.edu.buaa.crypto.signature.pks.bb08.BB08SignKeyPairGenerationParameter;
import cn.edu.buaa.crypto.signature.pks.bb08.BB08SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bb08.BB08Signer;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE engine.
 */
public class HIBBELLW16bEngine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW16bHIBBE";

    private static HIBBELLW16bEngine engine;
    private Signer signer = new PairingDigestSigner(new BB08Signer(), new SHA256Digest());
    private AsymmetricKeySerPairGenerator signKeyPairGenerator = new BB08SignKeyPairGenerator();
    private KeyGenerationParameters signKeyPairGenerationParameter =
            new BB08SignKeyPairGenerationParameter(PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512));

    public static HIBBELLW16bEngine getInstance() {
        if (engine == null) {
            engine = new HIBBELLW16bEngine();
        }
        return engine;
    }

    private HIBBELLW16bEngine() {

    }

    public void setSigner(Signer signer, AsymmetricKeySerPairGenerator signKeyPairGenerator, KeyGenerationParameters signKeyPairGenerationParameter) {
        this.signer = signer;
        this.signKeyPairGenerator = signKeyPairGenerator;
        this.signKeyPairGenerationParameter = signKeyPairGenerationParameter;
    }

    public AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
        HIBBELLW16bKeyPairGenerator keyPairGenerator = new HIBBELLW16bKeyPairGenerator();
        keyPairGenerator.init(new HIBBELLW16bKeyPairGenerationParameter(pairingParameters, signer, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance, find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16bPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW16bMasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance, find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBBELLW16aMasterSecretKeySerParameter.class.getName());
        }
        HIBBELLW16bSecretKeyGenerator secretKeyGenerator = new HIBBELLW16bSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW16bSecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public AsymmetricKeySerParameter delegate(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance, find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16bSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance, find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBBELLW16bSecretKeySerParameter.class.getName());
        }
        HIBBELLW16bSecretKeyGenerator secretKeyGenerator = new HIBBELLW16bSecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW16bDelegateGenerationParameter(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String... ids){
        if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance, find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16bPublicKeySerParameter.class.getName());
        }
        HIBBELLW16bEncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBBELLW16bEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBBELLW16bCiphertextGenerationParameter(
                signer, signKeyPairGenerator, signKeyPairGenerationParameter, publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, String[] ids, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW16bPublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance, find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW16bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW16bSecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance, find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBBELLW16bSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW16bCipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance, find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW16bCipherSerParameter.class.getName());
        }
        HIBBELLW16bDecapsulationGenerator keyDecapsulationGenerator = new HIBBELLW16bDecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBBELLW16bDecapsulationParameter(
                signer, publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }
}

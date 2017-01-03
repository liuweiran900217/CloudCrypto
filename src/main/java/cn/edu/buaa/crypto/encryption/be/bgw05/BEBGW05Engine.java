package cn.edu.buaa.crypto.encryption.be.bgw05;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.BEEngine;
import cn.edu.buaa.crypto.encryption.be.bgw05.generators.BEBGW05DecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.be.bgw05.generators.BEBGW05EncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.be.bgw05.generators.BEBGW05KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.be.bgw05.generators.BEBGW05SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.genparams.BEDecapsulationGenerationParameter;
import cn.edu.buaa.crypto.encryption.be.genparams.BEEncapsulationGenerationParameter;
import cn.edu.buaa.crypto.encryption.be.genparams.BEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.be.genparams.BESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Boneh-Gentry-Waters BE engine.
 */
public class BEBGW05Engine extends BEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "Boneh-Gentry-Waters BE";

    private static BEBGW05Engine engine;

    public static BEBGW05Engine getInstance() {
        if (engine == null) {
            engine = new BEBGW05Engine();
        }
        return engine;
    }

    private BEBGW05Engine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxUserNum) {
        BEBGW05KeyPairGenerator keyPairGenerator = new BEBGW05KeyPairGenerator();
        keyPairGenerator.init(new BEKeyPairGenerationParameter(pairingParameters, maxUserNum));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int index) {
        if (!(publicKey instanceof BEBGW05PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, BEBGW05PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof BEBGW05MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, BEBGW05MasterSecretKeySerParameter.class.getName());
        }
        BEBGW05SecretKeyGenerator secretKeyGenerator = new BEBGW05SecretKeyGenerator();
        secretKeyGenerator.init(new BESecretKeyGenerationParameter(
                publicKey, masterKey, index));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[] indexSet) {
        if (!(publicKey instanceof BEBGW05PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, BEBGW05PublicKeySerParameter.class.getName());
        }
        BEBGW05EncapsulationPairGenerator keyEncapsulationPairGenerator = new BEBGW05EncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new BEEncapsulationGenerationParameter(
                publicKey, indexSet));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[] indexSet, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof BEBGW05PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, BEBGW05PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof BEBGW05SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, BEBGW05SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof BEBGW05HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, BEBGW05HeaderSerParameter.class.getName());
        }
        BEBGW05DecapsulationGenerator keyDecapsulationGenerator = new BEBGW05DecapsulationGenerator();
        keyDecapsulationGenerator.init(new BEDecapsulationGenerationParameter(
                publicKey, secretKey, indexSet, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

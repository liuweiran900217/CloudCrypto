package cn.edu.buaa.crypto.encryption.ibbe;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.sepe.SelfExtractableBaseEngine;
import cn.edu.buaa.crypto.encryption.sepe.serparams.SEPEHeaderParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;

/**
 * Created by Weiran Liu on 2016/12/5.
 *
 * Self-extractable IBBE engine.
 */
public class SelfExtractableIBBEEngine extends Engine {
    private final IBBEEngine engine;
    private final SelfExtractableBaseEngine selfExtractableBaseEngine;

    public SelfExtractableIBBEEngine(IBBEEngine engine, PBEParametersGenerator pbeParametersGenerator, BlockCipher blockCipher, Digest digest) {
        super(engine.getEngineName(), engine.getProveSecModel(), engine.getPayloadSecLevel(), engine.getPredicateSecLevel());

        this.engine = engine;
        this.selfExtractableBaseEngine = new SelfExtractableBaseEngine(engine, pbeParametersGenerator, blockCipher, digest);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxUserNum) {
        return engine.setup(pairingParameters, maxUserNum);
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String identity) {
        return engine.keyGen(publicKey, masterKey, identity);
    }

    public byte[] selfKeyGen() {
        return this.selfExtractableBaseEngine.selfKeyGen();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] identitySet, byte[] ek){
        PairingKeyEncapsulationSerPair encapsulationPair = this.engine.encapsulation(publicKey, identitySet);
        return this.selfExtractableBaseEngine.encapsulation(encapsulationPair, ek);
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String[] identitySet, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(header instanceof SEPEHeaderParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(this.selfExtractableBaseEngine.getEngineName(), header,
                    SEPEHeaderParameter.class.getName());
        }
        SEPEHeaderParameter seHeaderParameter = (SEPEHeaderParameter)header;
        PairingCipherSerParameter headerParameter = seHeaderParameter.getCtY();
        byte[] ct_k = seHeaderParameter.getCtK();
        byte[] k_prime_temp = this.engine.decapsulation(publicKey, secretKey, identitySet, headerParameter);
        return this.selfExtractableBaseEngine.decapsulation(k_prime_temp, ct_k);
    }

    public byte[] selfDecapsulation(byte[] ek, PairingCipherSerParameter header) throws InvalidCipherTextException {
        return this.selfExtractableBaseEngine.selfDecapsulation(ek, header);
    }

    public String getEngineName() {
        return this.selfExtractableBaseEngine.getEngineName();
    }
}

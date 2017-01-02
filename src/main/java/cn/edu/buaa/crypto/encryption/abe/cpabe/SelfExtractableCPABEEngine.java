package cn.edu.buaa.crypto.encryption.abe.cpabe;

import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.sepe.SelfExtractableBaseEngine;
import cn.edu.buaa.crypto.encryption.sepe.serparams.SEPEHeaderParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;

/**
 * Created by Weiran Liu on 2016/12/4.
 *
 * Self-extractable CP-ABE engine.
 */
public class SelfExtractableCPABEEngine extends Engine {
    private final CPABEEngine engine;
    private final SelfExtractableBaseEngine selfExtractableBaseEngine;

    public boolean isSupportIntermediate() {
        return (this.engine instanceof OOCPABEEngine);
    }

    public SelfExtractableCPABEEngine(CPABEEngine engine, PBEParametersGenerator pbeParametersGenerator, BlockCipher blockCipher, Digest digest) {
        super(engine.getEngineName(), engine.getProveSecModel(), engine.getPayloadSecLevel(), engine.getPredicateSecLevel());
        this.engine = engine;
        this.selfExtractableBaseEngine = new SelfExtractableBaseEngine(engine, pbeParametersGenerator, blockCipher, digest);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributeNum) {
        return engine.setup(pairingParameters, maxAttributeNum);
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        return engine.keyGen(publicKey, masterKey, attributes);
    }

    public byte[] selfKeyGen() {
        return this.selfExtractableBaseEngine.selfKeyGen();
    }

    public PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n) {
        if (!(this.engine instanceof OOCPABEEngine)) {
            throw new IllegalArgumentException("Engine does not support online/offline mechanism");
        }
        OOCPABEEngine ooEngine = (OOCPABEEngine)this.engine;
        return ooEngine.offlineEncryption(publicKey, n);
    }

    public PairingKeyEncapsulationSerPair encapsulation(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
            String accessPolicy, byte[] ek) throws PolicySyntaxException {
        if (!(this.engine instanceof OOCPABEEngine)) {
            throw new IllegalArgumentException("Engine does not support online/offline mechanism");
        }
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return this.encapsulation(publicKey, intermediate, accessPolicyIntArrays, rhos, ek);
    }

    public PairingKeyEncapsulationSerPair encapsulation(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
            int[][] accessPolicyIntArrays, String[] rhos, byte[] ek) {
        if (!(this.engine instanceof OOCPABEEngine)) {
            throw new IllegalArgumentException("Engine does not support online/offline mechanism");
        }
        OOCPABEEngine ooEngine = (OOCPABEEngine)this.engine;
        PairingKeyEncapsulationSerPair encapsulationPair = ooEngine.encapsulation(publicKey, intermediate, accessPolicyIntArrays, rhos);
        return this.selfExtractableBaseEngine.encapsulation(encapsulationPair, ek);
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String accessPolicy, byte[] ek) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return encapsulation(publicKey, accessPolicyIntArrays, rhos, ek);
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, byte[] ek){
        PairingKeyEncapsulationSerPair encapsulationPair = this.engine.encapsulation(publicKey, accessPolicyIntArrays, rhos);
        return this.selfExtractableBaseEngine.encapsulation(encapsulationPair, ek);
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String accessPolicy, PairingCipherSerParameter header) throws PolicySyntaxException, InvalidCipherTextException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return decapsulation(publicKey, secretKey, accessPolicyIntArrays, rhos, header);
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(header instanceof SEPEHeaderParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + this.selfExtractableBaseEngine.getEngineName()  + ", find "
                            + header.getClass().getName() + ", require "
                            + SEPEHeaderParameter.class.getName());
        }
        SEPEHeaderParameter seHeaderParameter = (SEPEHeaderParameter)header;
        PairingCipherSerParameter headerParameter = seHeaderParameter.getCtY();
        byte[] ct_k = seHeaderParameter.getCtK();
        byte[] k_prime_temp = this.engine.decapsulation(publicKey, secretKey, accessPolicyIntArrays, rhos, headerParameter);
        return this.selfExtractableBaseEngine.decapsulation(k_prime_temp, ct_k);
    }

    public byte[] selfDecapsulation(byte[] ek, PairingCipherSerParameter header) throws InvalidCipherTextException {
        return this.selfExtractableBaseEngine.selfDecapsulation(ek, header);
    }

    public String getEngineName() {
        return this.selfExtractableBaseEngine.getEngineName();
    }

    public boolean isAccessControlEngineSupportThresholdGate() {
        return this.engine.isAccessControlEngineSupportThresholdGate();
    }
}

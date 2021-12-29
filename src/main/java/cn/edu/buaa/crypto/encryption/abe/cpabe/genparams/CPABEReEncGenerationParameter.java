package cn.edu.buaa.crypto.encryption.abe.cpabe.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingReEncGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class CPABEReEncGenerationParameter extends PairingReEncGenerationParameter {

    private AccessControlEngine accessControlEngine;
    private int[][] accessPolicy;
    private String[] rhos;

    public CPABEReEncGenerationParameter(PairingKeySerParameter publicKeyParameter,
                                         PairingKeySerParameter reKeyParameter,
                                         PairingCipherSerParameter cipherParameter,
                                         AccessControlEngine accessControlEngine,
                                         int[][] accessPolicy, String[] rhos) {
        super(publicKeyParameter, reKeyParameter, cipherParameter);
        this.accessControlEngine = accessControlEngine;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }

    public AccessControlEngine getAccessControlEngine() {
        return this.accessControlEngine;
    }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

    public String[] getRhos() { return this.rhos; }
}

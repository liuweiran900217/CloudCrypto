package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEIntermediateGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE intermediate ciphertext generator.
 */
public class KPABEHW14IntermediateGenerator implements PairingEncryptionGenerator {
    private KPABEIntermediateGenerationParameter parameter;
    private KPABEHW14PublicKeySerParameter publicKeyParameter;
    private int n;
    private Element sessionKey;
    private Element s;
    private Element C0;
    private Element[] rs;
    private Element[] xs;
    private Element[] C1s;
    private Element[] C2s;

    public void init(CipherParameters parameter) {
        this.parameter = (KPABEIntermediateGenerationParameter) parameter;
        this.publicKeyParameter = (KPABEHW14PublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    protected void computeEncapsulation() {
        this.n = parameter.getN();
        this.rs = new Element[n];
        this.xs = new Element[n];
        this.C1s = new Element[n];
        this.C2s = new Element[n];

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        this.s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
        this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();
        for (int i = 0; i < n; i++) {
            this.rs[i] = pairing.getZr().newRandomElement().getImmutable();
            this.xs[i] = pairing.getZr().newRandomElement().getImmutable();
            this.C1s[i] = publicKeyParameter.getG().powZn(rs[i]).getImmutable();
            this.C2s[i] = publicKeyParameter.getU().powZn(xs[i]).mul(publicKeyParameter.getH()).powZn(rs[i])
                    .mul(publicKeyParameter.getW().powZn(s.negate())).getImmutable();
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        return new KPABEHW14IntermediateSerParameter(publicKeyParameter.getParameters(), n, sessionKey, s,
                C0, rs, xs, C1s, C2s);
    }
}

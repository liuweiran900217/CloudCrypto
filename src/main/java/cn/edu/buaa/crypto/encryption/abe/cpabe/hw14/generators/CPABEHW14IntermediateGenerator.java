package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEIntermediateGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE intermediate ciphertext generator.
 */
public class CPABEHW14IntermediateGenerator implements PairingEncryptionGenerator {
    private CPABEIntermediateGenerationParameter parameter;
    private CPABEHW14PublicKeySerParameter publicKeyParameter;
    protected int n;
    protected Element sessionKey;
    protected Element s;
    protected Element C0;
    protected Element[] lambdas;
    protected Element[] ts;
    protected Element[] xs;
    protected Element[] C1s;
    protected Element[] C2s;
    protected Element[] C3s;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEIntermediateGenerationParameter) parameter;
        this.publicKeyParameter = (CPABEHW14PublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    protected void computeEncapsulation() {
        this.n = parameter.getN();
        this.lambdas = new Element[n];
        this.ts = new Element[n];
        this.xs = new Element[n];
        this.C1s = new Element[n];
        this.C2s = new Element[n];
        this.C3s = new Element[n];

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        this.s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
        this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();
        for (int i = 0; i < n; i++) {
            this.lambdas[i] = pairing.getZr().newRandomElement().getImmutable();
            this.ts[i] = pairing.getZr().newRandomElement().getImmutable();
            this.xs[i] = pairing.getZr().newRandomElement().getImmutable();
            this.C1s[i] = publicKeyParameter.getW().powZn(lambdas[i]).mul(publicKeyParameter.getV().powZn(ts[i])).getImmutable();
            this.C2s[i] = publicKeyParameter.getU().powZn(xs[i]).mul(publicKeyParameter.getH()).powZn(ts[i].negate()).getImmutable();
            this.C3s[i] = publicKeyParameter.getG().powZn(ts[i]).getImmutable();
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        return new CPABEHW14IntermediateSerParameter(publicKeyParameter.getParameters(), n, sessionKey, s,
                C0, lambdas, ts, xs, C1s, C2s, C3s);
    }
}
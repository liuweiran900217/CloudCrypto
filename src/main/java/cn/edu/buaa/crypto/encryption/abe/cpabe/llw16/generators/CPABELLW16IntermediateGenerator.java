package cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEIntermediateGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators.CPABEHW14IntermediateGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.io.IOException;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure CP-ABE intermediate generator.
 */
public class CPABELLW16IntermediateGenerator extends CPABEHW14IntermediateGenerator {
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerParameter chameleonHashPublicKey;
    private AsymmetricKeySerParameter chameleonHashSecretKey;
    private CPABELLW16PublicKeySerParameter publicKeyParameter;
    private Element C01;
    private Element C02;
    private Element C03;
    private byte[] chameleonHash;
    private byte[] r;

    public void init(CipherParameters parameter) {
        CPABEIntermediateGenerationParameter oriIntermediateGenParameter = (CPABEIntermediateGenerationParameter) parameter;
        this.chameleonHasher = oriIntermediateGenParameter.getChameleonHasher();
        AsymmetricKeySerPairGenerator chKeyPairGenerator = oriIntermediateGenParameter.getChameleonHashKeyPairGenerator();
        KeyGenerationParameters chKeyPairGenParameter = oriIntermediateGenParameter.getChameleonHashKeyGenerationParameter();
        chKeyPairGenerator.init(chKeyPairGenParameter);
        AsymmetricKeySerPair chKeyPair = chKeyPairGenerator.generateKeyPair();
        this.chameleonHashPublicKey = chKeyPair.getPublic();
        this.chameleonHashSecretKey = chKeyPair.getPrivate();
        this.publicKeyParameter = (CPABELLW16PublicKeySerParameter) oriIntermediateGenParameter.getPublicKeyParameter();
        CPABEIntermediateGenerationParameter resultIntermediateGenParameter = new CPABEIntermediateGenerationParameter(
                oriIntermediateGenParameter.getPublicKeyParameter(),
                oriIntermediateGenParameter.getN()
        );
        super.init(resultIntermediateGenParameter);
    }

    protected void computeEncapsulation() {
        super.computeEncapsulation();
        try {
            Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
            chameleonHasher.init(false, chameleonHashPublicKey);
            byte[] byteArrayChameleonHashPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
            chameleonHasher.update(byteArrayChameleonHashPublicKey, 0, byteArrayChameleonHashPublicKey.length);
            byte[][] chResult = chameleonHasher.computeHash();
            this.chameleonHash = chResult[0];
            this.r = chResult[1];
            Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
            String mappedStringV = tempV.toString();
            Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
            Element t0 = pairing.getZr().newRandomElement().getImmutable();
            this.C01 = publicKeyParameter.getW().powZn(s).mul(publicKeyParameter.getV().powZn(t0)).getImmutable();
            this.C03 = publicKeyParameter.getG().powZn(t0).getImmutable();
            this.C02 = publicKeyParameter.getU().powZn(V).mul(publicKeyParameter.getH()).powZn(t0.negate()).getImmutable();
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize chk.");
        } catch (CryptoException e) {
            throw new RuntimeException("Cannot compute chameleon hash.");
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        return new CPABELLW16IntermediateSerParameter(publicKeyParameter.getParameters(), n,
                chameleonHash, r, chameleonHashPublicKey, chameleonHashSecretKey, C01, C02, C03,
                sessionKey, s, C0, lambdas, ts, xs, C1s, C2s, C3s);
    }
}

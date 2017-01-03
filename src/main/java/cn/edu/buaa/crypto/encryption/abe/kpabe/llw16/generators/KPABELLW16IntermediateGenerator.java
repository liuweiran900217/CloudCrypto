package cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEIntermediateGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators.KPABEHW14IntermediateGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.KPABELLW16IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.KPABELLW16PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2017/1/3.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-KP-ABE intermediate generator.
 */
public class KPABELLW16IntermediateGenerator extends KPABEHW14IntermediateGenerator {
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerParameter chameleonHashPublicKey;
    private AsymmetricKeySerParameter chameleonHashSecretKey;
    private KPABELLW16PublicKeySerParameter publicKeyParameter;
    private Element C01;
    private Element C02;
    private byte[] chameleonHash;
    private byte[] r;

    public void init(CipherParameters parameter) {
        KPABEIntermediateGenerationParameter oriIntermediateGenParameter = (KPABEIntermediateGenerationParameter) parameter;
        this.chameleonHasher = oriIntermediateGenParameter.getChameleonHasher();
        AsymmetricKeySerPairGenerator chKeyPairGenerator = oriIntermediateGenParameter.getChameleonHashKeyPairGenerator();
        KeyGenerationParameters chKeyPairGenParameter = oriIntermediateGenParameter.getChameleonHashKeyGenerationParameter();
        chKeyPairGenerator.init(chKeyPairGenParameter);
        AsymmetricKeySerPair chKeyPair = chKeyPairGenerator.generateKeyPair();
        this.chameleonHashPublicKey = chKeyPair.getPublic();
        this.chameleonHashSecretKey = chKeyPair.getPrivate();
        this.publicKeyParameter = (KPABELLW16PublicKeySerParameter) oriIntermediateGenParameter.getPublicKeyParameter();
        KPABEIntermediateGenerationParameter resultIntermediateGenParameter = new KPABEIntermediateGenerationParameter(
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
            Element r0 = pairing.getZr().newRandomElement().getImmutable();
            this.C01 = publicKeyParameter.getG().powZn(r0).getImmutable();
            this.C02 = publicKeyParameter.getU().powZn(V).mul(publicKeyParameter.getH()).powZn(r0)
                    .mul(publicKeyParameter.getW().powZn(s.negate())).getImmutable();
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize chk.");
        } catch (CryptoException e) {
            throw new RuntimeException("Cannot compute chameleon hash.");
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        return new KPABELLW16IntermediateSerParameter(publicKeyParameter.getParameters(), n,
                chameleonHash, r, chameleonHashPublicKey, chameleonHashSecretKey, C01, C02,
                sessionKey, s, C0, rs, xs, C1s, C2s);
    }
}

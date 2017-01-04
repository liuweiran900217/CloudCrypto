package cn.edu.buaa.crypto.encryption.re.llw16b.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.re.genparams.REIntermediateGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.generators.RELLW16aIntermediateGenerator;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bIntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE intermediate ciphertext generator.
 */
public class RELLW16bIntermediateGenerator extends RELLW16aIntermediateGenerator {
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerParameter chameleonHashPublicKey;
    private AsymmetricKeySerParameter chameleonHashSecretKey;
    private RELLW16bPublicKeySerParameter publicKeyParameter;
    private Element C01;
    private Element C02;
    private byte[] chameleonHash;
    private byte[] r;

    public void init(CipherParameters parameter) {
        REIntermediateGenerationParameter oriIntermediateGenParameter = (REIntermediateGenerationParameter) parameter;
        this.chameleonHasher = oriIntermediateGenParameter.getChameleonHasher();
        AsymmetricKeySerPairGenerator chKeyPairGenerator = oriIntermediateGenParameter.getChameleonHashKeyPairGenerator();
        KeyGenerationParameters chKeyPairGenParameter = oriIntermediateGenParameter.getChameleonHashKeyGenerationParameter();
        chKeyPairGenerator.init(chKeyPairGenParameter);
        AsymmetricKeySerPair chKeyPair = chKeyPairGenerator.generateKeyPair();
        this.chameleonHashPublicKey = chKeyPair.getPublic();
        this.chameleonHashSecretKey = chKeyPair.getPrivate();
        this.publicKeyParameter = (RELLW16bPublicKeySerParameter) oriIntermediateGenParameter.getPublicKeyParameter();
        REIntermediateGenerationParameter resultIntermediateGenParameter = new REIntermediateGenerationParameter(
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
            this.C01 = publicKeyParameter.getGb().powZn(r0).getImmutable();
            this.C02 = publicKeyParameter.getGb2().powZn(V).mul(publicKeyParameter.getHb()).powZn(r0).getImmutable();
            this.C0 = this.C0.mul(publicKeyParameter.getG().powZn(r0)).getImmutable();
            this.sessionKey = this.sessionKey.mul(publicKeyParameter.getEggAlpha().powZn(r0));
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize chk.");
        } catch (CryptoException e) {
            throw new RuntimeException("Cannot compute chameleon hash.");
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        return new RELLW16bIntermediateSerParameter(publicKeyParameter.getParameters(), this.n,
                chameleonHash, r, chameleonHashPublicKey, chameleonHashSecretKey, C01, C02,
                sessionKey, s, C0, ss, xs, C1s, C2s);
    }
}

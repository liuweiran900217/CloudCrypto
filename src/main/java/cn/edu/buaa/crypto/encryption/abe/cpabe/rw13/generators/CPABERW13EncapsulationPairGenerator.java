package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13CiphertextGenerationParameters;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13CipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Ciphertext Encapsulation generator for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13EncapsulationPairGenerator implements PairingEncapsulationPairGenerator {
    private CPABERW13CiphertextGenerationParameters params;

    public void init(CipherParameters params) {
        this.params = (CPABERW13CiphertextGenerationParameters)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        CPABERW13PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        AccessControlEngine accessControlEngine = publicKeyParameters.getAccessControlEngine();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        int[][] accessPolicy = params.getAccessPolicy();
        String[] rhos = params.getRhos();
        Element[] elementRhos = PairingUtils.MapStringArrayToGroup(pairing, rhos, PairingUtils.PairingGroupType.Zr);

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = publicKeyParameters.getEggAlpha().powZn(s).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);
        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
        Element[] C1s = new Element[this.params.getLength()];
        Element[] C2s = new Element[this.params.getLength()];
        Element[] C3s = new Element[this.params.getLength()];

        Element C0 = publicKeyParameters.getG().powZn(s).getImmutable();
        for (int i = 0; i < rhos.length; i++) {
            Element ti = pairing.getZr().newRandomElement().getImmutable();
            Element lambda_i = lambdaElementsMap.get(rhos[i]).getImmutable();
            C1s[i] = publicKeyParameters.getW().powZn(lambda_i).mul(publicKeyParameters.getV().powZn(ti)).getImmutable();
            C2s[i] = publicKeyParameters.getU().powZn(elementRhos[i]).mul(publicKeyParameters.getH()).powZn(ti.negate()).getImmutable();
            C3s[i] = publicKeyParameters.getG().powZn(ti).getImmutable();
        }

        return new PairingKeyEncapsulationSerPair(
                byteArraySessionKey,
                new CPABERW13CipherSerParameter(publicKeyParameters.getParameters(), C0, C1s, C2s, C3s));
    }
}
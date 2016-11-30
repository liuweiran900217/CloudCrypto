package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Rouselakis-Waters KP-ABE secret key generator.
 */
public class KPABERW13SecretKeyGenerator implements PairingKeyParameterGenerator {
    private KPABESecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (KPABESecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        KPABERW13MasterSecretKeySerParameter masterSecretKeyParameter = (KPABERW13MasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        KPABERW13PublicKeySerParameter publicKeyParameter = (KPABERW13PublicKeySerParameter)parameters.getPublicKeyParameter();
        int[][] accessPolicy = this.parameters.getAccessPolicy();
        String[] stringRhos = this.parameters.getRhos();
        Map<String, Element> K0s = new HashMap<String, Element>();
        Map<String, Element> K1s = new HashMap<String, Element>();
        Map<String, Element> K2s = new HashMap<String, Element>();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            Element alpha = masterSecretKeyParameter.getAlpha().getImmutable();
            AccessControlParameter accessControlParameter =
                    this.parameters.getAccessControlEngine().generateAccessControl(accessPolicy, stringRhos);
            Map<String, Element> lambdaElementsMap = this.parameters.getAccessControlEngine().secretSharing(pairing, alpha, accessControlParameter);
            for (String rho : lambdaElementsMap.keySet()) {
                Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
                Element ti = pairing.getZr().newRandomElement().getImmutable();
                Element K0 = publicKeyParameter.getG().powZn(lambdaElementsMap.get(rho)).mul(publicKeyParameter.getW().powZn(ti)).getImmutable();
                K0s.put(rho, K0);
                Element K1 = publicKeyParameter.getU().powZn(elementRho).mul(publicKeyParameter.getH()).powZn(ti.negate()).getImmutable();
                K1s.put(rho, K1);
                Element K2 = publicKeyParameter.getG().powZn(ti).getImmutable();
                K2s.put(rho, K2);
            }
            return new KPABERW13SecretKeySerParameter(publicKeyParameter.getParameters(), accessControlParameter, K0s, K1s, K2s);
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }
}

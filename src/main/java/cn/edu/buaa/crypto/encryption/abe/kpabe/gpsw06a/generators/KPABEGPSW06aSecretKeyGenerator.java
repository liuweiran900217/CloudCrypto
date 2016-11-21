package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams.KPABEGPSW06aSecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE secret key generator.
 */
public class KPABEGPSW06aSecretKeyGenerator implements PairingKeyParameterGenerator {
    private KPABEGPSW06aSecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (KPABEGPSW06aSecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        KPABEGPSW06aMasterSecretKeySerParameter masterSecretKeyParameter = (KPABEGPSW06aMasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        KPABEGPSW06aPublicKeySerParameter publicKeyParameter = (KPABEGPSW06aPublicKeySerParameter)parameters.getPublicKeyParameter();
        assert(parameters.getRhos().length <= publicKeyParameter.getMaxAttributesNum());
        int[][] accessPolicy = this.parameters.getAccessPolicy();
        String[] stringRhos = this.parameters.getRhos();
        Map<String, Element> Ds = new HashMap<String, Element>();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            Element y = masterSecretKeyParameter.getY().getImmutable();
            AccessControlParameter accessControlParameter =
                    this.parameters.getAccessControlEngine().generateAccessControl(accessPolicy, stringRhos);
            Map<String, Element> lambdaElementsMap = this.parameters.getAccessControlEngine().secretSharing(pairing, y, accessControlParameter);
            for (String rho : lambdaElementsMap.keySet()) {
                int index = Integer.parseInt(rho);
                if (index >= publicKeyParameter.getMaxAttributesNum() || index < 0) {
                    throw new InvalidParameterException("Rho index greater than or equal to the max number of attributes supported");
                }
                Element d = publicKeyParameter.getG().powZn(lambdaElementsMap.get(rho).div(masterSecretKeyParameter.getTsAt(String.valueOf(index)))).getImmutable();
                Ds.put(String.valueOf(index), d);
            }
            return new KPABEGPSW06aSecretKeySerParameter(publicKeyParameter.getParameters(), accessControlParameter, Ds);
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }
}

package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15EncapsulationGenParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15EncapsulationParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15PublicKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generators.PairingKeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/19.
 */
public class RBACLLW15KeyEncapsulationParameters implements PairingKeyEncapsulationPairGenerator {
    private RBACLLW15EncapsulationGenParameters params;

    public void init(CipherParameters params) {
        this.params = (RBACLLW15EncapsulationGenParameters)params;
    }

    public PairingKeyEncapsulationPair generateEncryptionPair() {
        RBACLLW15PublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String id = this.params.getId();
        Element elementId = Utils.MapToZr(pairing, id);
        String time = this.params.getTime();
        Element elementTime = Utils.MapToZr(pairing, time);
        String[] roles = params.getRoles();
        Element[] elementRoles = Utils.MapToZr(pairing, roles);

        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2()).powZn(beta).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();

        Element C0 = publicKeyParameters.getG().powZn(beta).getImmutable();
        Element w = Utils.MapToZr(pairing, C0.toBytes());
        Element C1 = publicKeyParameters.getG3().getImmutable();
        //Multiply roles
        for (int i=0; i<publicKeyParameters.getMaxRoleNumber(); i++){
            if (roles[i] != null){
                C1 = C1.mul(publicKeyParameters.getUsAt(i).powZn(elementRoles[i])).getImmutable();
            }
        }
        //Multiply id
        C1 = C1.mul(publicKeyParameters.getGh().powZn(elementId)).getImmutable();
        //Multiply time
        C1 = C1.mul(publicKeyParameters.getU0().powZn(elementTime)).getImmutable();
        //Multiply verification attribute
        C1 = C1.mul(publicKeyParameters.getUv().powZn(w)).getImmutable();
        C1 = C1.powZn(beta).getImmutable();
        return new PairingKeyEncapsulationPair(
                Arrays.copyOf(byteArraySessionKey, byteArraySessionKey.length),
                new RBACLLW15EncapsulationParameters(publicKeyParameters.getParameters(), C0, C1));
    }
}
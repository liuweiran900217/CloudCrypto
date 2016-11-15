package cn.edu.buaa.crypto.encryption.ibbe.del07.generators;

import cn.edu.buaa.crypto.algebra.algorithms.HornerRule;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07CipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.genparams.IBBEDel07DecapsulationParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07SecretKeySerParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Key decapsulation generator for Delerablée IBBE scheme.
 */
public class IBBEDel07DecapsulationGenerator implements PairingDecapsulationGenerator {
    private IBBEDel07DecapsulationParameter params;

    public void init(CipherParameters params) {
        this.params = (IBBEDel07DecapsulationParameter)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        IBBEDel07PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        IBBEDel07SecretKeySerParameter secretKeyParameters = this.params.getSecretKeyParameters();
        IBBEDel07CipherSerParameter ciphertextParameters = this.params.getCiphertextParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());

        int index;
        //test if the user is in the broadcast receiver set
        for (index = 0; index < params.getNumberOfBroadcastReceiver(); index++) {
            if (secretKeyParameters.getId().equals(params.getIdsAt(index))) {
                break;
            }
        }
        //user is not in the broadcast receiver set
        if (index >= params.getNumberOfBroadcastReceiver()) {
            throw new InvalidCipherTextException("User identity is not in the broadcast receiver set, cannot decapsulate...");
        }

        Element[] elementsIdsWithoutTarget = new Element[this.params.getNumberOfBroadcastReceiver() - 1];
        for (int i = 0, j = 0; i < params.getNumberOfBroadcastReceiver(); i++) {
            if (i != index) {
                elementsIdsWithoutTarget[j] = PairingUtils.MapStringToGroup(pairing, this.params.getIdsAt(i), PairingUtils.PairingGroupType.Zr).getImmutable();
                j++;
            }
        }

        //decapsulation
        Element[] coefficientsForP = HornerRule.ComputeEfficients(pairing, elementsIdsWithoutTarget);
        Element temp1 = pairing.getG2().newOneElement().getImmutable();

        for (int i = 1; i < coefficientsForP.length; i++) {
            temp1 = temp1.mul(publicKeyParameters.getHsAt(i-1).powZn(coefficientsForP[i])).getImmutable();
        }

        Element tempPow = pairing.getZr().newOneElement().getImmutable();
        for (Element anElementsIdsWithoutTarget : elementsIdsWithoutTarget) {
            tempPow = tempPow.mulZn(anElementsIdsWithoutTarget).getImmutable();
        }
        tempPow = tempPow.invert().getImmutable();

        Element sessionKey = pairing.pairing(ciphertextParameters.getC1(), temp1)
                .mul(pairing.pairing(secretKeyParameters.getSecretKey(), ciphertextParameters.getC2()))
                .powZn(tempPow).getImmutable();
        return sessionKey.toBytes();
    }
}

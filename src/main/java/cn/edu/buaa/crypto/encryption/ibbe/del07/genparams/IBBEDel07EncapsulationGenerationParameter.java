package cn.edu.buaa.crypto.encryption.ibbe.del07.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncapsulationGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Ciphertext generation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07EncapsulationGenerationParameter extends PairingEncapsulationGenerationParameter {
    private String[] ids;

    public IBBEDel07EncapsulationGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] ids) {
        super(publicKeyParameter);
        this.ids = PairingUtils.removeDuplicates(ids);
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

package cn.edu.buaa.crypto.encryption.ibbe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncapsulationGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * IBBE encapsulation generation parameter.
 */
public class IBBEEncapsulationGenerationParameter extends PairingEncapsulationGenerationParameter {
    private String[] ids;

    public IBBEEncapsulationGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] ids) {
        super(publicKeyParameter);
        this.ids = PairingUtils.removeDuplicates(ids);
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

package cn.edu.buaa.crypto.encryption.re.oolsw10a.serialization;

import cn.edu.buaa.crypto.encryption.re.oolsw10a.OORELSW10aEngine;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.w3c.dom.Document;

/**
 * Created by Weiran Liu on 16/4/10.
 */
public class OORELSW10aXMLSerializer implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = OORELSW10aEngine.SCHEME_NAME;

    //Tags for public key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_Gb = "Gb";
    private static final String TAG_PK_Gb2 = "Gb2";
    private static final String TAG_PK_Hb = "Hb";
    private static final String TAG_PK_EggAlpha = "EggAlpha";

    //Tags for master secret key
    private static final String TAG_MSK_ALPHA = "Alpha";
    private static final String TAG_MSK_B = "b";
    private static final String TAG_MSK_H = "h";

    //Tags for secret key
    private static final String TAG_SK_ID = "id";
    private static final String TAG_SK_D0 = "d0";
    private static final String TAG_SK_D1 = "d1";
    private static final String TAG_SK_D2 = "d2";

    //Tags for intermediate ciphertext
    private static final String TAG_ICT_KEY = "Key";
    private static final String TAG_ICT_C0 = "C0";
    private static final String TAG_ICT_CIS = "C1s";
    private static final String TAG_ICT_C1I = "C1i";
    private static final String TAG_ICT_C2S = "C2s";
    private static final String TAG_ICT_C2I = "C2i";
    private static final String TAG_ICT_CV1 = "Cv1";
    private static final String TAG_ICT_CV2 = "Cv2";
    private static final String TAG_ICT_IS = "Is";
    private static final String TAG_ICT_II = "Ii";
    private static final String TAG_ICT_IV = "Iv";
    private static final String TAG_ICT_SS = "Ss";
    private static final String TAG_ICT_SI = "Si";
    private static final String TAG_ICT_SV = "Sv";
    private static final String TAG_ICT_S = "S";
    private static final String TAG_ICT_CH_SK = "CHSecretKey";
    private static final String TAG_ICT_CH_RES = "CHHashResult";

    //Tags for ciphertext
    private static final String TAG_CT_C0 = "C0";
    private static final String TAG_CT_C1S = "C1s";
    private static final String TAG_CT_C1I = "C1i";
    private static final String TAG_CT_C2S = "C2s";
    private static final String TAG_CT_C2I = "C2i";
    private static final String TAG_CT_CV1 = "Cv1";
    private static final String TAG_CT_CV2 = "Cv2";
    private static final String TAG_CT_IMALLS = "Imalls";
    private static final String TAG_CT_IMALLI = "Imalli";
    private static final String TAG_CT_CH_PK = "CHPublicKey";
    private static final String TAG_CT_CH_RES = "CHHashResult";

    private static final OORELSW10aXMLSerializer INSTANCE = new OORELSW10aXMLSerializer();

    private OORELSW10aXMLSerializer() { }

    public static OORELSW10aXMLSerializer getInstance(){
        return INSTANCE;
    }


    public Document documentSerialization(CipherParameters cipherParameters) {
        return null;
    }

    public CipherParameters documentDeserialization(PairingParameters pairingParameters, Document document) {
        return null;
    }
}

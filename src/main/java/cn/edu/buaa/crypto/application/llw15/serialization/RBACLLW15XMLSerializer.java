package cn.edu.buaa.crypto.application.llw15.serialization;

import cn.edu.buaa.crypto.utils.SerializationUtils;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import cn.edu.buaa.crypto.application.llw15.params.*;
import cn.edu.buaa.crypto.algebra.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 16/6/20.
 *
 * Liu-Liu-Wu role-based access conrol scheme XML serializer.
 */
public class RBACLLW15XMLSerializer  implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = RBACLLW15Engine.SCHEME_NAME;


    private static final String TYPE_PK = "PK";
    private static final String TYPE_MSK = "MSK";
    private static final String TYPE_ACM = "ACM";
    private static final String TYPE_ACP = "ACP";
    private static final String TYPE_ENC = "ENC";
    private static final String TYPE_IMP = "IMP";

    //Tags for public key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_G1 = "G1";
    private static final String TAG_PK_G2 = "G2";
    private static final String TAG_PK_G3 = "G3";
    private static final String TAG_PK_GH = "Gh";
    private static final String TAG_PK_U0 = "U0";
    private static final String TAG_PK_UV = "Uv";
    private static final String TAG_PK_US = "Us";
    private static final String TAG_PK_UI = "Ui";

    //Tags for master secret key
    private static final String TAG_MSK_G2ALPHA = "G2Alpha";

    //Tags for medical staff access credential
    private static final String TAG_ACM_A0 = "a0";
    private static final String TAG_ACM_A1 = "a1";
    private static final String TAG_ACM_A2 = "a2";
    private static final String TAG_ACM_BV = "bv";
    private static final String TAG_ACM_BS = "bs";
    private static final String TAG_ACM_BI = "bi";
    private static final String TAG_ACM_ROLES = "Roles";
    private static final String TAG_ACM_ROLEI = "Rolei";
    private static final String TAG_ACM_TIME = "Time";

    //Tags for patient access credential
    private static final String TAG_ACP_A0 = "a0";
    private static final String TAG_ACP_A1 = "a1";
    private static final String TAG_ACP_B0 = "b0";
    private static final String TAG_ACP_BV = "bv";
    private static final String TAG_ACP_BS = "bs";
    private static final String TAG_ACP_BI = "bi";
    private static final String TAG_ACP_ID = "id";

    //Tags for ciphertexts
    private static final String TAG_ENC_C0 = "C0";
    private static final String TAG_ENC_C1 = "C1";

    //Tags for intermediate parameters
    private static final String TAG_IMP_r = "r";
    private static final String TAG_IMP_G3_r = "G3_r";
    private static final String TAG_IMP_Gh_r = "Gh_r";
    private static final String TAG_IMP_G_r = "G_r";
    private static final String TAG_IMP_U0_r = "U0_r";
    private static final String TAG_IMP_Uv_r = "Uv_r";
    private static final String TAG_IMP_Us_r = "Us_r";
    private static final String TAG_IMP_Ui_r = "Ui_r";

    private static final RBACLLW15XMLSerializer INSTANCE = new RBACLLW15XMLSerializer();

    private RBACLLW15XMLSerializer() { }

    public static RBACLLW15XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof RBACLLW15PublicKeyParameters) {
            return getInstance().publicKeyParametersSerialization((RBACLLW15PublicKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof RBACLLW15MasterSecretKeyParameters) {
            return getInstance().masterSecretKeyParametersSerialization((RBACLLW15MasterSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof RBACLLW15AccessCredentialMParameters) {
            return getInstance().accessCredentialMParametersSerialization((RBACLLW15AccessCredentialMParameters) cipherParameters);
        } else if (cipherParameters instanceof RBACLLW15AccessCredentialPParameters) {
            return getInstance().accessCredentialPParametersSerialization((RBACLLW15AccessCredentialPParameters) cipherParameters);
        } else if (cipherParameters instanceof RBACLLW15EncapsulationParameters) {
            return getInstance().encapsulationParametersSerialization((RBACLLW15EncapsulationParameters) cipherParameters);
        } else if (cipherParameters instanceof  RBACLLW15IntermediateParameters) {
            return getInstance().intermediateParametersSerialization((RBACLLW15IntermediateParameters) cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + RBACLLW15Engine.SCHEME_NAME
                    + " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(RBACLLW15PublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, TYPE_PK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH, Integer.toString(publicKeyParameters.getMaxRoleNumber()));
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G, publicKeyParameters.getG());
            //Set g1
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G1, publicKeyParameters.getG1());
            //Set g2
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G2, publicKeyParameters.getG2());
            //Set g3
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G3, publicKeyParameters.getG3());
            //Set gh
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_GH, publicKeyParameters.getGh());
            //Set u0
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_U0, publicKeyParameters.getU0());
            //Set uv
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_UV, publicKeyParameters.getUv());
            //Set u
            SerializationUtils.SetElementArray(publicKeyParametersDocument, schemeElement, TAG_PK_US, TAG_PK_UI, publicKeyParameters.getUs());
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(RBACLLW15MasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set g2Alpha
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_G2ALPHA, masterSecretKeyParameters.getG2Alpha());
            return masterSecretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document accessCredentialMParametersSerialization(RBACLLW15AccessCredentialMParameters accessCredentialMParameters){
        try {
            Document accessCredentialMDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = accessCredentialMDocument.createElement(TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, TYPE_ACM);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH, Integer.toString(accessCredentialMParameters.getBs().length));
            accessCredentialMDocument.appendChild(schemeElement);
            //Set Roles
            SerializationUtils.SetStringArray(accessCredentialMDocument, schemeElement, TAG_ACM_ROLES, TAG_ACM_ROLEI, accessCredentialMParameters.getRoles());
            //Set Time
            SerializationUtils.SetString(accessCredentialMDocument, schemeElement, TAG_ACM_TIME, accessCredentialMParameters.getTime());
            //Set a0
            SerializationUtils.SetElement(accessCredentialMDocument, schemeElement, TAG_ACM_A0, accessCredentialMParameters.getA0());
            //Set a1
            SerializationUtils.SetElement(accessCredentialMDocument, schemeElement, TAG_ACM_A1, accessCredentialMParameters.getA1());
            //Set a2
            SerializationUtils.SetElement(accessCredentialMDocument, schemeElement, TAG_ACM_A2, accessCredentialMParameters.getA2());
            //Set bv
            SerializationUtils.SetElement(accessCredentialMDocument, schemeElement, TAG_ACM_BV, accessCredentialMParameters.getBv());
            //Set bs
            SerializationUtils.SetElementArray(accessCredentialMDocument, schemeElement, TAG_ACM_BS, TAG_ACM_BI, accessCredentialMParameters.getBs());
            return accessCredentialMDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document accessCredentialPParametersSerialization(RBACLLW15AccessCredentialPParameters accessCredentialPParameters){
        try {
            Document accessCredentialPDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = accessCredentialPDocument.createElement(TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, TYPE_ACP);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH, Integer.toString(accessCredentialPParameters.getBsPrime().length));
            accessCredentialPDocument.appendChild(schemeElement);
            //Set Identity
            SerializationUtils.SetString(accessCredentialPDocument, schemeElement, TAG_ACP_ID, accessCredentialPParameters.getId());
            //Set a0
            SerializationUtils.SetElement(accessCredentialPDocument, schemeElement, TAG_ACP_A0, accessCredentialPParameters.getA0Prime());
            //Set a1
            SerializationUtils.SetElement(accessCredentialPDocument, schemeElement, TAG_ACP_A1, accessCredentialPParameters.getA1Prime());
            //Set b0
            SerializationUtils.SetElement(accessCredentialPDocument, schemeElement, TAG_ACP_B0, accessCredentialPParameters.getB0Prime());
            //Set bv
            SerializationUtils.SetElement(accessCredentialPDocument, schemeElement, TAG_ACP_BV, accessCredentialPParameters.getBvPrime());
            //Set bs
            SerializationUtils.SetElementArray(accessCredentialPDocument, schemeElement, TAG_ACP_BS, TAG_ACP_BI, accessCredentialPParameters.getBsPrime());
            return accessCredentialPDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document encapsulationParametersSerialization(RBACLLW15EncapsulationParameters encapsulationParameters){
        try {
            Document encapsulationDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = encapsulationDocument.createElement(TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, TYPE_ENC);
            encapsulationDocument.appendChild(schemeElement);
            //Set C0
            SerializationUtils.SetElement(encapsulationDocument, schemeElement, TAG_ENC_C0, encapsulationParameters.getC0());
            //Set C1
            SerializationUtils.SetElement(encapsulationDocument, schemeElement, TAG_ENC_C1, encapsulationParameters.getC1());
            return encapsulationDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document intermediateParametersSerialization(RBACLLW15IntermediateParameters intermediateParameters) {
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, TYPE_IMP);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH, Integer.toString(intermediateParameters.get_U_s_r().length));
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g_r
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_IMP_r, intermediateParameters.get_r());
            //Set g_3_r
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_IMP_G3_r, intermediateParameters.get_G_3_r());
            //Set g_h_r
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_IMP_Gh_r, intermediateParameters.get_G_h_r());
            //Set g_r
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_IMP_G_r, intermediateParameters.get_G_r());
            //Set u_0_r
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_IMP_U0_r, intermediateParameters.get_U_0_r());
            //Set u_v_r
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_IMP_Uv_r, intermediateParameters.get_U_v_r());
            //Set u
            SerializationUtils.SetElementArray(publicKeyParametersDocument, schemeElement, TAG_IMP_Us_r, TAG_IMP_Ui_r, intermediateParameters.get_U_s_r());
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    public CipherParameters documentDeserialization(PairingParameters pairingParameters, Document document) {
        Element schemeElement = document.getDocumentElement();
        String cipherParameterType = schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_TYPE);
        if (cipherParameterType.equals(TYPE_PK)){
            return getInstance().publicKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(TYPE_MSK)){
            return getInstance().masterSecretKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(TYPE_ACM)) {
            return getInstance().accessCredentialMParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(TYPE_ACP)) {
            return getInstance().accessCredentialPParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(TYPE_ENC)) {
            return getInstance().encapsulationParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(TYPE_IMP)) {
            return getInstance().intermediateParametersDeserialization(pairingParameters, schemeElement);
        } else {
            throw new InvalidParameterException("Illegal " + RBACLLW15XMLSerializer.TAG_SCHEME_NAME +
                    " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element g1 = null;
        it.unisa.dia.gas.jpbc.Element g2 = null;
        it.unisa.dia.gas.jpbc.Element g3 = null;
        it.unisa.dia.gas.jpbc.Element gh = null;
        it.unisa.dia.gas.jpbc.Element u0 = null;
        it.unisa.dia.gas.jpbc.Element uv = null;
        it.unisa.dia.gas.jpbc.Element[] us = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
               g = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_G1)) {
                //Set g1
                g1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_G2)) {
                //Set g2
                g2 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_G3)) {
                //Set g3
                g3 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_GH)) {
                //Set gh
                gh = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_U0)) {
                //Set u0
                u0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_UV)) {
                //Set uv
                uv = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_US)) {
                //Set us
                us = SerializationUtils.GetElementArray(pairing, node, TAG_PK_UI, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new RBACLLW15PublicKeyParameters(pairingParameters, g, g1, g2, g3, gh, u0, uv, us);
    }

    private CipherParameters masterSecretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g2Alpha = null;
        for (int i=0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            //Set g2Alpha
            if (node.getNodeName().equals(TAG_MSK_G2ALPHA)) {
                g2Alpha = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new RBACLLW15MasterSecretKeyParameters(pairingParameters, g2Alpha);
    }

    private CipherParameters accessCredentialMParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        String[] roles = null;
        it.unisa.dia.gas.jpbc.Element[] elementRoles;
        String time = null;
        it.unisa.dia.gas.jpbc.Element elementTime;
        it.unisa.dia.gas.jpbc.Element a0 = null;
        it.unisa.dia.gas.jpbc.Element a1 = null;
        it.unisa.dia.gas.jpbc.Element a2 = null;
        it.unisa.dia.gas.jpbc.Element bv = null;
        it.unisa.dia.gas.jpbc.Element[] bs = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_ACM_A0)) {
                //Set a0
                a0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ACM_A1)) {
                //Set a1
                a1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ACM_A2)) {
                //Set a2
                a2 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ACM_BV)) {
                //Set bv
                bv = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ACM_TIME)) {
                //Set time
                time = node.getFirstChild().getNodeValue();
            } else if (node.getNodeName().equals(TAG_ACM_BS)) {
                //Set bs
                bs = SerializationUtils.GetElementArray(pairing, node, TAG_ACM_BI, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ACM_ROLES)) {
                //Set roles
                roles = SerializationUtils.GetStringArray(node, TAG_ACM_ROLEI);
            }
        }
        elementTime = PairingUtils.MapToZr(pairing, time);
        elementRoles = PairingUtils.MapToZr(pairing, roles);
        return new RBACLLW15AccessCredentialMParameters(pairingParameters, roles, elementRoles, time, elementTime,
                a0, a1, a2, bv, bs);
    }

    private CipherParameters accessCredentialPParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        String identity = null;
        it.unisa.dia.gas.jpbc.Element a0 = null;
        it.unisa.dia.gas.jpbc.Element a1 = null;
        it.unisa.dia.gas.jpbc.Element b0 = null;
        it.unisa.dia.gas.jpbc.Element bv = null;
        it.unisa.dia.gas.jpbc.Element[] bs = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_ACP_A0)) {
                //Set a0
                a0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ACP_A1)) {
                //Set a1
                a1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ACP_B0)) {
                //Set b0
                b0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ACP_BV)) {
                //Set bv
                bv = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ACP_ID)) {
                //Set identity
                identity = node.getFirstChild().getNodeValue();
            } else if (node.getNodeName().equals(TAG_ACM_BS)) {
                //Set bs
                bs = SerializationUtils.GetElementArray(pairing, node, TAG_ACM_BI, SerializationUtils.PairingGroupType.G1);
            }
        }
        it.unisa.dia.gas.jpbc.Element elementId = PairingUtils.MapToZr(pairing, identity);
        return new RBACLLW15AccessCredentialPParameters(pairingParameters, identity, elementId,
                a0, a1, b0, bv, bs);
    }

    private CipherParameters encapsulationParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element C0 = null;
        it.unisa.dia.gas.jpbc.Element C1 = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_ENC_C0)) {
                //Set C0
                C0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ENC_C1)) {
                //Set C1
                C1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new RBACLLW15EncapsulationParameters(pairingParameters, C0, C1);
    }

    private CipherParameters intermediateParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element r = null;
        it.unisa.dia.gas.jpbc.Element g_3_r = null;
        it.unisa.dia.gas.jpbc.Element g_h_r = null;
        it.unisa.dia.gas.jpbc.Element g_r = null;
        it.unisa.dia.gas.jpbc.Element u_0_r = null;
        it.unisa.dia.gas.jpbc.Element u_v_r = null;
        it.unisa.dia.gas.jpbc.Element[] u_s_r = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_IMP_r)) {
                //Set r
                r = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_IMP_G3_r)) {
                //Set g_3_r
                g_3_r = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_IMP_Gh_r)) {
                //Set g_h_r
                g_h_r = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_IMP_G_r)) {
                //Set g_r
                g_r = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_IMP_U0_r)) {
                //Set u_0_r
                u_0_r = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_IMP_Uv_r)) {
                //Set u_v_r
                u_v_r = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_IMP_Us_r)) {
                //Set us
                u_s_r = SerializationUtils.GetElementArray(pairing, node, TAG_IMP_Ui_r, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new RBACLLW15IntermediateParameters(r, g_3_r, g_h_r, g_r, u_0_r, u_v_r, u_s_r);
    }
}

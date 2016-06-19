package cn.edu.buaa.crypto.application.llw15.serialization;

import cn.edu.buaa.crypto.SerializationUtils;
import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import cn.edu.buaa.crypto.application.llw15.params.*;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 16/6/20.
 */
public class RBACLLW15XMLSerializer  implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = RBACLLW15Engine.SCHEME_NAME;


    private static final String TYPE_PK = "PK";
    private static final String TYPE_MSK = "MSK";
    private static final String TYPE_ACM = "ACM";
    private static final String TYPE_ACP = "ACP";
    private static final String TYPE_ENC = "ENC";

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
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + RBACLLW15Engine.SCHEME_NAME
                    + " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(RBACLLW15PublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(this.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, this.TYPE_PK);
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
            Element schemeElement = masterSecretKeyDocument.createElement(this.TAG_SCHEME_NAME);
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
            Element schemeElement = accessCredentialMDocument.createElement(this.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, this.TYPE_ACM);
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
            Element schemeElement = accessCredentialPDocument.createElement(this.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, this.TYPE_ACP);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH, Integer.toString(accessCredentialPParameters.getBs().length));
            accessCredentialPDocument.appendChild(schemeElement);
            //Set Identity
            SerializationUtils.SetString(accessCredentialPDocument, schemeElement, TAG_ACP_ID, accessCredentialPParameters.getId());
            //Set a0
            SerializationUtils.SetElement(accessCredentialPDocument, schemeElement, TAG_ACP_A0, accessCredentialPParameters.getA0());
            //Set a1
            SerializationUtils.SetElement(accessCredentialPDocument, schemeElement, TAG_ACP_A1, accessCredentialPParameters.getA1());
            //Set b0
            SerializationUtils.SetElement(accessCredentialPDocument, schemeElement, TAG_ACP_B0, accessCredentialPParameters.getB0());
            //Set bv
            SerializationUtils.SetElement(accessCredentialPDocument, schemeElement, TAG_ACP_BV, accessCredentialPParameters.getBv());
            //Set bs
            SerializationUtils.SetElementArray(accessCredentialPDocument, schemeElement, TAG_ACP_BS, TAG_ACP_BI, accessCredentialPParameters.getBs());
            return accessCredentialPDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document encapsulationParametersSerialization(RBACLLW15EncapsulationParameters encapsulationParameters){
        try {
            Document encapsulationDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = encapsulationDocument.createElement(this.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, this.TYPE_ENC);
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

    public CipherParameters documentDeserialization(PairingParameters pairingParameters, Document document) {
        Element schemeElement = document.getDocumentElement();
        String cipherParameterType = schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_TYPE);
        if (cipherParameterType.equals(this.TYPE_PK)){
            return getInstance().publicKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(this.TYPE_MSK)){
            return getInstance().masterSecretKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(this.TYPE_ACM)) {
            return getInstance().accessCredentialMParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(this.TYPE_ACP)) {
            return getInstance().accessCredentialPParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(this.TYPE_ENC)) {
            return getInstance().encapsulationParametersDeserialization(pairingParameters, schemeElement);
        } else {
            throw new InvalidParameterException("Illegal " + RBACLLW15XMLSerializer.TAG_SCHEME_NAME +
                    " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int maxRoleNumber = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element g1 = null;
        it.unisa.dia.gas.jpbc.Element g2 = null;
        it.unisa.dia.gas.jpbc.Element g3 = null;
        it.unisa.dia.gas.jpbc.Element gh = null;
        it.unisa.dia.gas.jpbc.Element u0 = null;
        it.unisa.dia.gas.jpbc.Element uv = null;
        it.unisa.dia.gas.jpbc.Element[] us = new it.unisa.dia.gas.jpbc.Element[maxRoleNumber];
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
                String gString = node.getFirstChild().getNodeValue();
                g = pairing.getG1().newElementFromBytes(Hex.decode(gString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_G1)) {
                //Set g1
                String g1String = node.getFirstChild().getNodeValue();
                g1 = pairing.getG1().newElementFromBytes(Hex.decode(g1String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_G2)) {
                //Set g2
                String g2String = node.getFirstChild().getNodeValue();
                g2 = pairing.getG1().newElementFromBytes(Hex.decode(g2String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_G3)) {
                //Set g3
                String g3String = node.getFirstChild().getNodeValue();
                g3 = pairing.getG1().newElementFromBytes(Hex.decode(g3String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_GH)) {
                //Set gh
                String ghString = node.getFirstChild().getNodeValue();
                gh = pairing.getG1().newElementFromBytes(Hex.decode(ghString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_U0)) {
                //Set u0
                String u0String = node.getFirstChild().getNodeValue();
                u0 = pairing.getG1().newElementFromBytes(Hex.decode(u0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_UV)) {
                //Set uv
                String uvString = node.getFirstChild().getNodeValue();
                uv = pairing.getG1().newElementFromBytes(Hex.decode(uvString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_US)) {
                //Set us
                NodeList nodeHsList = ((Element) node).getElementsByTagName(TAG_PK_UI);
                for (int j=0; j<nodeHsList.getLength(); j++) {
                    Element elementUi = (Element)nodeHsList.item(j);
                    int index = Integer.valueOf(elementUi.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    String uiString = elementUi.getFirstChild().getNodeValue();
                    us[index] = pairing.getG1().newElementFromBytes(Hex.decode(uiString)).getImmutable();
                }
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
                String g2AlphaString = node.getFirstChild().getNodeValue();
                g2Alpha = pairing.getG1().newElementFromBytes(Hex.decode(g2AlphaString)).getImmutable();
            }
        }
        return new RBACLLW15MasterSecretKeyParameters(pairingParameters, g2Alpha);
    }

    private CipherParameters accessCredentialMParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int maxRoleNumber = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        String[] roles = new String[maxRoleNumber];
        it.unisa.dia.gas.jpbc.Element[] elementRoles;
        String time = null;
        it.unisa.dia.gas.jpbc.Element elementTime = null;
        it.unisa.dia.gas.jpbc.Element a0 = null;
        it.unisa.dia.gas.jpbc.Element a1 = null;
        it.unisa.dia.gas.jpbc.Element a2 = null;
        it.unisa.dia.gas.jpbc.Element bv = null;
        it.unisa.dia.gas.jpbc.Element[] bs = new it.unisa.dia.gas.jpbc.Element[maxRoleNumber];
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_ACM_A0)) {
                //Set a0
                String a0String = node.getFirstChild().getNodeValue();
                a0 = pairing.getG1().newElementFromBytes(Hex.decode(a0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_ACM_A1)) {
                //Set a1
                String a1String = node.getFirstChild().getNodeValue();
                a1 = pairing.getG1().newElementFromBytes(Hex.decode(a1String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_ACM_A2)) {
                //Set a2
                String a2String = node.getFirstChild().getNodeValue();
                a2 = pairing.getG1().newElementFromBytes(Hex.decode(a2String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_ACM_BV)) {
                //Set bv
                String bvString = node.getFirstChild().getNodeValue();
                bv = pairing.getG1().newElementFromBytes(Hex.decode(bvString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_ACM_TIME)) {
                //Set time
                time = node.getFirstChild().getNodeValue();
            } else if (node.getNodeName().equals(TAG_ACM_BS)) {
                //Set bs
                NodeList nodeBsList = ((Element) node).getElementsByTagName(TAG_ACM_BI);
                for (int j=0; j<nodeBsList.getLength(); j++) {
                    Element elementBi = (Element) nodeBsList.item(j);
                    int index = Integer.valueOf(elementBi.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    String biString = elementBi.getFirstChild().getNodeValue();
                    bs[index] = pairing.getG1().newElementFromBytes(Hex.decode(biString)).getImmutable();
                }
            } else if (node.getNodeName().equals(TAG_ACM_ROLES)) {
                //Set roles
                NodeList nodeIdsList = ((Element) node).getElementsByTagName(TAG_ACM_ROLEI);
                for (int j=0; j<nodeIdsList.getLength(); j++) {
                    Element elementIdi = (Element)nodeIdsList.item(j);
                    int index = Integer.valueOf(elementIdi.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    if (elementIdi.hasChildNodes()) {
                        roles[index] = elementIdi.getFirstChild().getNodeValue();
                    }
                }
            }
        }
        elementTime = Utils.MapToZr(pairing, time);
        elementRoles = Utils.MapToZr(pairing, roles);
        return new RBACLLW15AccessCredentialMParameters(pairingParameters, roles, elementRoles, time, elementTime,
                a0, a1, a2, bv, bs);
    }

    private CipherParameters accessCredentialPParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int maxRoleNumber = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        String identity = null;
        it.unisa.dia.gas.jpbc.Element elementId = null;
        it.unisa.dia.gas.jpbc.Element a0 = null;
        it.unisa.dia.gas.jpbc.Element a1 = null;
        it.unisa.dia.gas.jpbc.Element b0 = null;
        it.unisa.dia.gas.jpbc.Element bv = null;
        it.unisa.dia.gas.jpbc.Element[] bs = new it.unisa.dia.gas.jpbc.Element[maxRoleNumber];
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_ACP_A0)) {
                //Set a0
                String a0String = node.getFirstChild().getNodeValue();
                a0 = pairing.getG1().newElementFromBytes(Hex.decode(a0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_ACP_A1)) {
                //Set a1
                String a1String = node.getFirstChild().getNodeValue();
                a1 = pairing.getG1().newElementFromBytes(Hex.decode(a1String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_ACP_B0)) {
                //Set b0
                String b0String = node.getFirstChild().getNodeValue();
                b0 = pairing.getG1().newElementFromBytes(Hex.decode(b0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_ACP_BV)) {
                //Set bv
                String bvString = node.getFirstChild().getNodeValue();
                bv = pairing.getG1().newElementFromBytes(Hex.decode(bvString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_ACP_ID)) {
                //Set identity
                identity = node.getFirstChild().getNodeValue();
            } else if (node.getNodeName().equals(TAG_ACM_BS)) {
                //Set bs
                NodeList nodeBsList = ((Element) node).getElementsByTagName(TAG_ACM_BI);
                for (int j=0; j<nodeBsList.getLength(); j++) {
                    Element elementBi = (Element) nodeBsList.item(j);
                    int index = Integer.valueOf(elementBi.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    String biString = elementBi.getFirstChild().getNodeValue();
                    bs[index] = pairing.getG1().newElementFromBytes(Hex.decode(biString)).getImmutable();
                }
            }
        }
        elementId = Utils.MapToZr(pairing, identity);
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
                String c0String = node.getFirstChild().getNodeValue();
                C0 = pairing.getG1().newElementFromBytes(Hex.decode(c0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_ENC_C1)) {
                //Set C1
                String c1String = node.getFirstChild().getNodeValue();
                C1 = pairing.getG1().newElementFromBytes(Hex.decode(c1String)).getImmutable();
            }
        }
        return new RBACLLW15EncapsulationParameters(pairingParameters, C0, C1);
    }
}

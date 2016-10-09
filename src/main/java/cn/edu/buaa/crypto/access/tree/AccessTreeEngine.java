package cn.edu.buaa.crypto.access.tree;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.AccessTreeNode;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.algebra.LagrangePolynomial;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/20.
 *
 * This is the implementation of the access tree scheme proposed first proposed by Goyal, Pandey, Sahai, Waters in 2006.
 * Conference version: V. Goyal, O. Pandey, A. Sahai, B. Waters. Attribute-based encryption for fine-grained access control of encrypted data. CCS 2006, 89-98.
 */
public class AccessTreeEngine implements AccessControlEngine {
    public static String SCHEME_NAME = "General Access Tree Method";

    private static AccessTreeEngine instance = new AccessTreeEngine();

    private AccessTreeEngine() {

    }

    public static AccessTreeEngine getInstance() {
        return instance;
    }

    public String getEngineName() {
        return this.SCHEME_NAME;
    }

    public boolean isSupportThresholdGate() {
        return true;
    }

    public AccessControlParameter generateAccessControl(int[][] accessPolicy, String[] rhos) {
        //init access tree
        AccessTreeNode accessTreeNode = AccessTreeNode.GenerateAccessTree(accessPolicy, rhos);
        return new AccessControlParameter(accessTreeNode, accessPolicy, rhos);
    }

    public Map<String, Element> secretSharing(Pairing pairing, Element secret, AccessControlParameter accessControlParameter) {
        Map<String, Element> sharedElementsMap = new HashMap<String, Element>();
        access_tree_node_secret_sharing(pairing, secret, accessControlParameter.getRootAccessTreeNode(), sharedElementsMap);
        return sharedElementsMap;
    }

    private void access_tree_node_secret_sharing(Pairing pairing, Element rootSecret, AccessTreeNode accessTreeNode, Map<String, Element> sharingResult) {
        if (accessTreeNode.isLeafNode()) {
            //leaf node, add root secret into the map
            sharingResult.put(accessTreeNode.getAttribute(), rootSecret.duplicate().getImmutable());
        } else {
            //non-leaf nodes, share secrets to child nodes
            LagrangePolynomial lagrangePolynomial = new LagrangePolynomial(pairing, accessTreeNode.getT() - 1, rootSecret);
            for (int i = 0; i < accessTreeNode.getN(); i++) {
                Element sharedSecret = lagrangePolynomial.evaluate(pairing.getZr().newElement(i + 1));
                access_tree_node_secret_sharing(pairing, sharedSecret, accessTreeNode.getChildNodeAt(i), sharingResult);
            }
        }
    }

    public Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes, AccessControlParameter accessControlParameter)
            throws UnsatisfiedAccessControlException {
        Map<String, String> collisionMap = new HashMap<String, String>();
        for (int i = 0; i < attributes.length; i++) {
            if (collisionMap.containsKey(attributes[i])) {
                throw new UnsatisfiedAccessControlException("Invalid attribute set, containing identical attribute: " + attributes[i]);
            } else {
                collisionMap.put(attributes[i], attributes[i]);
            }
        }
        SatisfiedAccessTreeNode satisfiedAccessTreeNode = SatisfiedAccessTreeNode.GetSatisfiedAccessTreeNode(pairing, accessControlParameter.getRootAccessTreeNode());
        return SatisfiedAccessTreeNode.CalCoefficient(satisfiedAccessTreeNode, attributes);
    }

    private static class SatisfiedAccessTreeNode {
        private final Pairing pairing;
        private final SatisfiedAccessTreeNode parentNode;
        private final SatisfiedAccessTreeNode[] childNodes;
        private final int index;
        private final int label;
        private final int t;
        private final int n;
        private final boolean isLeafNode;
        private final String attribute;
        private int[] satisfiedIndex;
        private boolean isSatisfied;

        public static SatisfiedAccessTreeNode GetSatisfiedAccessTreeNode(Pairing pairing, AccessTreeNode rootAccessTreeNode) {
            return new SatisfiedAccessTreeNode(pairing, null, 0, rootAccessTreeNode);
        }

        public static Map<String, Element> CalCoefficient(SatisfiedAccessTreeNode rootSatisfiedAccessTreeNode, String[] attributes) throws UnsatisfiedAccessControlException {
            if (!rootSatisfiedAccessTreeNode.isAccessControlSatisfied(attributes)) {
                throw new UnsatisfiedAccessControlException("Give attribute set does not satisfy access policy");
            } else {
                Map<String, Element> coefficientElementsMap = new HashMap<String, Element>();
                rootSatisfiedAccessTreeNode.calcCoefficients(coefficientElementsMap);
                return coefficientElementsMap;
            }
        }

        private SatisfiedAccessTreeNode(Pairing pairing, final SatisfiedAccessTreeNode parentSatisfiedAccessTreeNode, int index, final AccessTreeNode accessTreeNode) {
            this.pairing = pairing;
            this.parentNode = parentSatisfiedAccessTreeNode;
            this.index = index;
            this.label = accessTreeNode.getLabel();
            if (accessTreeNode.isLeafNode()) {
                this.childNodes = null;
                this.t = 0;
                this.n = 0;
                this.attribute = accessTreeNode.getAttribute();
                this.isLeafNode = true;
                return;
            } else {
                this.t = accessTreeNode.getT();
                this.n = accessTreeNode.getN();
                this.isLeafNode = false;
                this.attribute = null;
                this.childNodes = new SatisfiedAccessTreeNode[this.n];
                for (int i = 0; i < this.childNodes.length; i++) {
                    this.childNodes[i] = new SatisfiedAccessTreeNode(pairing, this, i + 1, accessTreeNode.getChildNodeAt(i));
//                    System.out.println("Node: " + this.childNodes[i].label + " with parentNode: " + this.label);
                }
            }
        }

        private boolean isAccessControlSatisfied(final String[] attributes) {
            this.isSatisfied = false;
            if (!this.isLeafNode) {
                int[] tempIndex = new int[this.childNodes.length];
                int satisfiedChildNumber = 0;
                for (int i = 0; i < this.childNodes.length; i++) {
                    if (childNodes[i].isAccessControlSatisfied(attributes)) {
                        tempIndex[i] = i + 1;
                        satisfiedChildNumber++;
                    }
                }
                this.satisfiedIndex = new int[satisfiedChildNumber];
                for (int i = 0, j = 0; i < this.childNodes.length; i++) {
                    if (tempIndex[i] > 0) {
                        this.satisfiedIndex[j] = tempIndex[i];
                        j++;
                    }
                }
//                System.out.println("Node " + this.label + " has satisfied child nodes " + satisfiedChildNumber);
                this.isSatisfied = (satisfiedChildNumber >= t);
            } else {
                for (int i = 0; i < attributes.length; i++) {
                    if (this.attribute.equals(attributes[i])) {
                        this.isSatisfied = true;
                    }
                }
            }
            return this.isSatisfied;
        }

        private void calcCoefficients(Map<String, Element> coefficientElementsMap) {
            if (!this.isLeafNode && this.isSatisfied) {
                for (int i = 0; i < this.childNodes.length; i++) {
                    if (this.childNodes[i].isSatisfied) {
                        this.childNodes[i].calcCoefficients(coefficientElementsMap);
                    }
                }
            } else {
                if (!this.isSatisfied) {
                    return;
                }
                SatisfiedAccessTreeNode currentNode = this;
                Element coefficientElement =  pairing.getZr().newOneElement().getImmutable();
                while (currentNode.parentNode != null) {
                    int currentIndex = currentNode.index;
                    currentNode = currentNode.parentNode;
                    coefficientElement = coefficientElement.mulZn(LagrangePolynomial.calCoef(pairing, currentNode.satisfiedIndex, currentIndex)).getImmutable();
                }
                coefficientElementsMap.put(this.attribute, coefficientElement);
            }
        }
    }
}

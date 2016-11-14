package cn.edu.buaa.crypto.access;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/19.
 *
 * Generic access tree node
 */
public class AccessTreeNode implements java.io.Serializable {
    private static int numberOfLeafNodes = 0;
    public static AccessTreeNode GenerateAccessTree(final int[][] accessPolicy, final String[] rhos) {
        Map<String, String> collisionMap = new HashMap<String, String>();
        for (String rho : rhos) {
            if (collisionMap.containsKey(rho)) {
                throw new InvalidParameterException("Invalid access policy, rhos containing identical string: " + rho);
            } else {
                collisionMap.put(rho, rho);
            }
        }
        numberOfLeafNodes = 0;
        AccessTreeNode rootAccessTreeNode = new AccessTreeNode(accessPolicy, 0, rhos);
        if (numberOfLeafNodes != rhos.length) {
            throw new InvalidParameterException("Invalid access policy, number of leaf nodes " + numberOfLeafNodes
                    + " does not match number of rhos " + rhos.length);
        }
        return rootAccessTreeNode;
    }

    private final AccessTreeNode[] childNodes;
    private final int t;
    private final int label;
    private final String attribute;
    private final boolean isLeafNode;

    private AccessTreeNode(final int i, final String rho) {
        this.childNodes = null;
        this.t = 0;
        this.label = i;
        this.isLeafNode = true;
        this.attribute = rho;
    }

    private AccessTreeNode(final int[][] accessPolicy, final int i, final String[] rhos) {
        int[] accessPolicyNode = accessPolicy[i];
        if (accessPolicyNode[0] < accessPolicyNode[1]) {
            throw new InvalidParameterException("Invalid access policy, n < t in the threahold gate " + i);
        }
        this.childNodes = new AccessTreeNode[accessPolicyNode[0]];
        this.t = accessPolicyNode[1];
        this.label = i;
        this.attribute = null;
        this.isLeafNode = false;
        int k = 0;
        for (int j = 2; j < accessPolicyNode.length; j++) {
            if (accessPolicyNode[j] > 0) {
                this.childNodes[k] = new AccessTreeNode(accessPolicy, accessPolicyNode[j], rhos);
            } else if (accessPolicyNode[j] < 0) {
                numberOfLeafNodes++;
                this.childNodes[k] = new AccessTreeNode(accessPolicyNode[j], rhos[-accessPolicyNode[j] - 1]);
            } else {
                throw new InvalidParameterException("Invalid access policy, containing access node with index 0");
            }
            k++;
        }
    }

    boolean isAccessControlSatisfied(final String[] attributes) {
        if (!this.isLeafNode) {
            int satisfiedChildNumber = 0;
            for (AccessTreeNode childNode : this.childNodes) {
                if (childNode.isAccessControlSatisfied(attributes)) {
                    satisfiedChildNumber++;
                }
            }
            return (satisfiedChildNumber >= t);
        } else {
            for (String eachAttribute : attributes) {
                if (this.attribute.equals(eachAttribute)) {
                    return true;
                }
            }
            return false;
        }
    }

    public int getT() {
        return this.t;
    }

    public int getN() {
        return this.childNodes.length;
    }

    public AccessTreeNode getChildNodeAt(int index) {
        return this.childNodes[index];
    }

    public boolean isLeafNode() {
        return this.isLeafNode;
    }

    public String getAttribute() {
        return this.attribute;
    }

    public int getLabel() {
        return this.label;
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof AccessTreeNode) {
            AccessTreeNode that = (AccessTreeNode) anOjbect;
            //Compare t;
            if (this.t != that.getT()) {
                return false;
            }
            //Compare label
            if (this.label != that.getLabel()) {
                return false;
            }
            //Compare leafnode
            if (this.isLeafNode) {
                //Compare attribute
                if (!this.attribute.equals(that.attribute)) {
                    return false;
                }
                return this.isLeafNode == that.isLeafNode;
            } else {
                //Compare nonleaf nodes
                if (this.childNodes.length != that.childNodes.length) {
                    return false;
                }
                for (int i = 0; i < this.childNodes.length; i++) {
                    //Compare child nodes
                    if (!this.childNodes[i].equals(that.getChildNodeAt(i))) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }
}
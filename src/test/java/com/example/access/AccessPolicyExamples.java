package com.example.access;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Access policy examples, used for testing AccessControlEngine and Attribute-Based Encryption schemes.
 */
public class AccessPolicyExamples {

    public static final String access_policy_example_1 = "0 and 1 and (2 or 3)";
    public static final String[] access_policy_exampe_1_satisfied_1 = new String[] {"0", "1", "2"};
    public static final String[] access_policy_exampe_1_satisfied_2 = new String[] {"0", "1", "2", "3"};
    public static final String[] access_policy_exampe_1_unsatisfied_1 = new String[] {"1", "2", "3"};

    public static final String access_policy_example_2 = "((0 and 1 and 2) and (3 or 4 or 5) and (6 and 7 and (8 or 9 or 10 or 11)))";
    public static final String[] access_policy_exampe_2_satisfied_1 = new String[] {"0", "1", "2", "4", "6", "7", "10"};
    public static final String[] access_policy_exampe_2_satisfied_2 = new String[] {"0", "1", "2", "5", "4", "6", "7", "8", "9", "10", "11"};
    public static final String[] access_policy_exampe_2_unsatisfied_1 = new String[] {"0", "1", "2", "6", "7", "10"};
    public static final String[] access_policy_exampe_2_unsatisfied_2 = new String[] {"0", "1", "2", "4", "6", "10"};
    public static final String[] access_policy_exampe_2_unsatisfied_3 = new String[] {"0", "1", "2", "3", "6", "7"};

    public static final String access_policy_example_3 =
            "00 and 01 and 02 and 03 and 04 and 05 and 06 and 07 and 08 and 09 and " +
            "10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and " +
            "20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and " +
            "30 and 31 and 32 and 33 and 34 and 35 and 36 and 37 and 38 and 39 and " +
            "40 and 41 and 42 and 43 and 44 and 45 and 46 and 47 and 48 and 49";
    public static final String[] access_policy_exampe_3_satisfied_1 = new String[] {
            "00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31", "32", "33", "34", "35", "36", "37", "38", "39",
            "40", "41", "42", "43", "44", "45", "46", "47", "48", "49",
    };
    public static final String[] access_policy_exampe_3_unsatisfied_1 = new String[] {
            "00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31", "32", "33", "34", "35", "36", "37", "38", "39",
            "40", "41", "42", "43", "44", "45", "46", "47", "48",
    };
    public static final String[] access_policy_exampe_3_unsatisfied_2 = new String[] {
            "04", "05", "06", "07", "08", "09",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31", "32", "33", "34",              "37", "38", "39",
            "40", "41", "42", "43", "44", "45", "46", "47", "48", "49",
    };

    public static final int[][] access_policy_threshold_example_1_tree = {
            {3, 2, 1, 2, 3},
            {3, 2, -1, -2, -3},
            {3, 2, -4, -5, -6},
            {3, 2, -7, -8, 4},
            {4, 3, -9, -10, -11, -12},
    };
    public static final String[] access_policy_threshold_example_1_rho = new String[] {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10","11",
    };
    public static final String[] access_policy_threshold_example_1_satisfied01 = new String[] {
            "0", "1", "3", "4",
    };
    public static final String[] access_policy_threshold_example_1_satisfied02 = new String[] {
            "0", "1", "6", "7",
    };
    public static final String[] access_policy_threshold_example_1_satisfied03 = new String[] {
            "0", "1", "6", "8", "9", "10",
    };
    public static final String[] access_policy_threshold_example_1_satisfied04 = new String[] {
            "1", "2", "7", "8", "10", "11",
    };
    public static final String[] access_policy_threshold_example_1_satisfied05 = new String[] {
            "3", "5", "6", "7",
    };
    public static final String[] access_policy_threshold_example_1_satisfied06 = new String[] {
            "3", "5", "7", "8", "10", "11",
    };
    public static final String[] access_policy_threshold_example_1_satisfied07 = new String[] {
            "4", "5", "7", "9", "10", "11",
    };
    public static final String[] access_policy_threshold_example_1_satisfied08 = new String[] {
            "0", "1", "2", "3", "4",
    };
    public static final String[] access_policy_threshold_example_1_satisfied09 = new String[] {
            "3", "4", "5", "6", "8", "9", "10", "11",
    };
    public static final String[] access_policy_threshold_example_1_satisfied10 = new String[] {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10","11",
    };
    public static final String[] access_policy_threshold_example_1_satisfied11 = new String[] {
            "11", "10", "8", "9", "4", "5", "6", "3", "2", "0", "1", "7",
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied01 = new String[] {
            "0", "3", "6", "8", "9",
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied02 = new String[] {
            "0", "3", "6", "7",
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied03 = new String[] {
            "0", "4", "8", "9", "10",
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied04 = new String[] {
            "1", "2", "5", "6", "10",
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied05 = new String[] {
            "3", "5", "2", "7", "10", "11"
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied06 = new String[] {
            "3", "5", "7", "8", "10", "10"
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied07 = new String[] {
            "3", "4", "4", "8", "9", "10", "10"
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied08 = new String[] {
            "0", "1", "2", "3", "-5",
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied09 = new String[] {
            "5", "8", "9", "10", "14", "20",
    };

    public static final int[][] access_policy_threshold_example_2_tree = {
            {2,2,1,2}, //the root node 0 is a 2of2 threshold and its children are nodes 1 and 2 (at rows 1 and 2) <br>
            {2,2,3,4}, //node 1 is a 1of2 threshold and its children are nodes 3 and 4 <br>
            {4,3,-7,-8,-9,-10}, //node 2 note that -5 here correponds to index of attribute E in the alphabet<br>
            {2,2,-2,5}, //node 3 <br>
            {3,2,-4,-5,-6}, //node 4 <br>
            {2,1,-1,-3} //node 5 <br>
    };
    public static final String[] access_policy_threshold_example_2_rho = new String[] {
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
    };
    public static final String[] access_policy_threshold_example_2_satisfied01 = new String[] {
            "2", "3", "5", "6", "7", "9", "10",
    };
    public static final String[] access_policy_threshold_example_2_unsatisfied01 = new String[] {
            "1", "3", "4", "6", "7", "9", "10",
    };
    public static final String[] access_policy_threshold_example_2_unsatisfied02 = new String[] {
            "2", "3", "5", "6", "8", "9",
    };
}

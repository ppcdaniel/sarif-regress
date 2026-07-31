final class StableCases {
    void exactCases(RuntimeException exception) {
        // HOLDOUT:pmd-exact-01
        exception.printStackTrace();
        // HOLDOUT:pmd-exact-02
        exception.printStackTrace();
        // HOLDOUT:pmd-exact-03
        exception.printStackTrace();
        // HOLDOUT:pmd-exact-04
        exception.printStackTrace();
        // HOLDOUT:pmd-exact-05
        exception.printStackTrace();
    }

    void messageCases(RuntimeException exception) {
        // HOLDOUT:pmd-message-modified-01
        exception.printStackTrace();
        // HOLDOUT:pmd-message-modified-02
        exception.printStackTrace();
        // HOLDOUT:pmd-message-modified-03
        exception.printStackTrace();
        // HOLDOUT:pmd-message-modified-04
        exception.printStackTrace();
        // HOLDOUT:pmd-message-modified-05
        exception.printStackTrace();
    }

    String neutralPadding() {
        return "alpha-beta-gamma";
    }

    void movedCases(RuntimeException exception) {
        // HOLDOUT:pmd-moved-01
        exception.printStackTrace();
        // HOLDOUT:pmd-moved-02
        exception.printStackTrace();
        // HOLDOUT:pmd-moved-03
        exception.printStackTrace();
        // HOLDOUT:pmd-moved-04
        exception.printStackTrace();
        // HOLDOUT:pmd-moved-05
        exception.printStackTrace();
    }

    void lineShiftCases(RuntimeException exception) {
        // Controlled insertion above the first finding.
        // HOLDOUT:pmd-line-shift-01
        exception.printStackTrace();
        // Controlled insertion A above the second finding.
        // Controlled insertion B above the second finding.
        // HOLDOUT:pmd-line-shift-02
        exception.printStackTrace();
        // Controlled insertion A above the third finding.
        // Controlled insertion B above the third finding.
        // Controlled insertion C above the third finding.
        // HOLDOUT:pmd-line-shift-03
        exception.printStackTrace();
        // Controlled insertion A above the fourth finding.
        // Controlled insertion B above the fourth finding.
        // Controlled insertion C above the fourth finding.
        // Controlled insertion D above the fourth finding.
        // HOLDOUT:pmd-line-shift-04
        exception.printStackTrace();
        // Controlled insertion A above the fifth finding.
        // Controlled insertion B above the fifth finding.
        // Controlled insertion C above the fifth finding.
        // Controlled insertion D above the fifth finding.
        // Controlled insertion E above the fifth finding.
        // HOLDOUT:pmd-line-shift-05
        exception.printStackTrace();
    }
}

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

    String neutralPadding() {
        return "alpha-beta-gamma";
    }

    void lineShiftCases(RuntimeException exception) {
        // HOLDOUT:pmd-line-shift-01
        exception.printStackTrace();
        // HOLDOUT:pmd-line-shift-02
        exception.printStackTrace();
        // HOLDOUT:pmd-line-shift-03
        exception.printStackTrace();
        // HOLDOUT:pmd-line-shift-04
        exception.printStackTrace();
        // HOLDOUT:pmd-line-shift-05
        exception.printStackTrace();
    }
}

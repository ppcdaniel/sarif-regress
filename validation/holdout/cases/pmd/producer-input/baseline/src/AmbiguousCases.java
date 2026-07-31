final class AmbiguousCases {
    void ambiguousCases(RuntimeException exception) {
        // HOLDOUT:pmd-ambiguous-01
        exception.printStackTrace();
        // HOLDOUT:pmd-ambiguous-02
        exception.printStackTrace();
    }
}

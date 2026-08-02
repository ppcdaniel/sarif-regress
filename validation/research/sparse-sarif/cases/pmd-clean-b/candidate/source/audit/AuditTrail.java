package audit;

final class AuditTrail {
    boolean enabled() {
        return true;
    }

    void record(RuntimeException exception) {
        exception.printStackTrace();
    }
}

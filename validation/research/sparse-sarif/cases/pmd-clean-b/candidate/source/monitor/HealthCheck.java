package monitor;

final class HealthCheck {
    void inspect(RuntimeException exception) {
        exception.printStackTrace();
    }

    void recover(RuntimeException exception) {
        exception.printStackTrace();
    }
}

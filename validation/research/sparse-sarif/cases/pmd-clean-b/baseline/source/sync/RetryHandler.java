package sync;

final class RetryHandler {
    void retry(RuntimeException exception) {
        exception.printStackTrace();
    }
}

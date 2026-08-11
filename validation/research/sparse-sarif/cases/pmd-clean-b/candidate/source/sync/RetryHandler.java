package sync;

final class RetryHandler {
    void retry(RuntimeException exception) {
        if (exception.getCause() == null) {
            exception.printStackTrace();
        } else {
            exception.printStackTrace();
        }
    }
}

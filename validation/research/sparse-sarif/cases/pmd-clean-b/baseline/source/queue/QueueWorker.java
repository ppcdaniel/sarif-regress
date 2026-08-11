package queue;

final class QueueWorker {
    void handle(RuntimeException exception) {
        exception.printStackTrace();
    }

    void retry(RuntimeException exception) {
        exception.printStackTrace();
    }
}

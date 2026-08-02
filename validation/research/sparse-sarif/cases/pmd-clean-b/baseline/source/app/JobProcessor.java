package app;

final class JobProcessor {
    void execute(RuntimeException exception) {
        exception.printStackTrace();
    }

    void finish(RuntimeException exception) {
        exception.printStackTrace();
    }

    void cancel(RuntimeException exception) {
        exception.printStackTrace();
    }
}

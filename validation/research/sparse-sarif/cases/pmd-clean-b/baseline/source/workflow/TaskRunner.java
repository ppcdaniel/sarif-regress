package workflow;

final class TaskRunner {
    void record(RuntimeException exception) {
        exception.printStackTrace();
    }
}

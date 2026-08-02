package service;

final class ReportService {
    void publish(RuntimeException exception) {
        exception.printStackTrace();
    }

    void archive(RuntimeException exception) {
        exception.printStackTrace();
    }
}

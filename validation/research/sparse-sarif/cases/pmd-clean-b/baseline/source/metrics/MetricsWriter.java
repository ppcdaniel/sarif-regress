package metrics;

final class MetricsWriter {
    void flush(RuntimeException exception) {
        exception.printStackTrace();
    }
}

package archive;

final class ImportTask {
    void load(RuntimeException exception) {
        exception.printStackTrace();
    }

    void reject(RuntimeException exception) {
        exception.printStackTrace();
    }
}

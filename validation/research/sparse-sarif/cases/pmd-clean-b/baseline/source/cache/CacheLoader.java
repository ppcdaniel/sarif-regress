package cache;

final class CacheLoader {
    void load(RuntimeException exception) {
        if (exception.getCause() == null) {
            exception.printStackTrace();
        } else {
            exception.printStackTrace();
        }
    }
}

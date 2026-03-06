import java.io.InputStream;
import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;

public final class DefragmentStream extends InputStream {
	private static final InputStream POISON = new InputStream() {
		@Override public int read() throws IOException { return -1; }
	}

	private volatile boolean closed = false;
	private InputStream current;
	private final LinkedBlockingQueue<InputStream> list = new LinkedBlockingQueue<>();
	@Override
	public int read() throws IOException {
		if (closed) return -1;
		try {
			while (true) {
				if (current == null) current = list.take();
				if (current == POISON) {
					list.add(current);
					return -1;
				}
				int result = current.read();
				if (result != -1) return result;
				current.close();
				current = null;
			}
		} catch (InterruptedException interrupt) {
			throw new IOException(interrupt);
		} catch (IOException e) {
			throw e;
		}
	}
	@Override
	public int read(byte[] arg0) throws IOException {
		if (closed) return -1;
		try {
			while (true) {
				if (current == null) current = list.take();
				if (current == POISON) {
					list.add(current);
					return -1;
				}
				int result = current.read(arg0);
				if (result != -1) return result;
				current.close();
				current = null;
			}
		} catch (InterruptedException interrupt) {
			throw new IOException(interrupt);
		} catch (IOException e) {
			throw e;
		}
	}
	@Override
	public int read(byte[] arg0, int arg1, int arg2) throws IOException {
		if (closed) return -1;
		try {
			while (true) {
				if (current == null) current = list.take();
				if (current == POISON) {
					list.add(current);
					return -1;
				}
				int result = current.read(arg0, arg1, arg2);
				if (result != -1) return result;
				current.close();
				current = null;
			}
		} catch (InterruptedException interrupt) {
			throw new IOException(interrupt);
		} catch (IOException e) {
			throw e;
		}
	}
	@Override
	public void close() throws IOException {
		if (closed) return;
		closed = true;
		IOException ex = null;
		if (current != null) try {
			current.close();
		} catch (IOException e) {
			ex = e;
		}
		InputStream stream;
		while ((stream = list.poll()) != null) {
			try {
				stream.close();
			} catch (IOException e) {
				if (ex == null) {
					ex = e;
				} else {
					ex.addSuppressed(e);
				}
			}
		}
		list.add(POISON);
		if (ex != null) throw ex;
	}

	public void addStream(InputStream stream) {
		if (closed) return;
		list.add(stream);
	}
}
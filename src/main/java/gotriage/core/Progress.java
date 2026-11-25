package gotriage.core;

/** Progress/cancellation callback, bridged to Ghidra's TaskMonitor in the plugin. */
public interface Progress {

	void update(String message, long current, long max);

	boolean isCancelled();

	Progress NONE = new Progress() {
		@Override
		public void update(String message, long current, long max) {
		}

		@Override
		public boolean isCancelled() {
			return false;
		}
	};
}

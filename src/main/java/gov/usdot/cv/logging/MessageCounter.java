package gov.usdot.cv.logging;

public class MessageCounter {
	
	public final String counterType;
	private int totalCount;
	private int successCount;

	public MessageCounter(String counterType) {
		this.counterType = counterType;
		totalCount = 0;
		successCount = 0;
	}
	
	public void incrementSuccess() {
		successCount++;
	}
	
	public void incrementTotal() {
		totalCount++;
	}
	
	public int getSuccessCount() {
		return successCount;
	}
	
	public int getTotalCount() {
		return totalCount;
	}

}

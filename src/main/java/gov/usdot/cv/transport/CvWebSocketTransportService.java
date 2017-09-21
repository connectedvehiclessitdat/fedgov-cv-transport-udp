package gov.usdot.cv.transport;

import org.apache.log4j.Logger;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import com.deleidos.rtws.core.framework.Description;
import com.deleidos.rtws.core.framework.UserConfigured;
import com.deleidos.rtws.transport.AbstractTransportService;

import gov.usdot.asn1.generated.j2735.J2735;
import gov.usdot.cv.logging.MessageCounting;
import gov.usdot.cv.websocket.WebSocketSSLHelper;
import gov.usdot.cv.websocket.WebSocketServer;

@Description("Listens via a WebSocketServer for messages to transport into the system")
public class CvWebSocketTransportService extends AbstractTransportService {

	private static final Logger logger = Logger.getLogger(CvWebSocketTransportService.class
			.getName());
	
	private WebSocketServer wsServer;
	private int listenPort;
	private boolean secure;
	private String keystorePath;
	private String keystorePassword;
	private boolean terminate = false;
	
	@Override
	public void initialize() {
		super.initialize();
		try {
			SslContextFactory sslContextFactory = null;
			if (secure) {
				sslContextFactory = WebSocketSSLHelper.buildServerSslContextFactory(keystorePath, keystorePassword);
			}
			wsServer = new WebSocketServer(getListenPort(), sslContextFactory);
			wsServer.addMessageProcessor(new WSMessageProcessor(this, wsServer));
			wsServer.start();
		} catch (Exception e) {
			logger.error("Failed to start WebSocket Server", e);
		}
	}
	
	public void execute() {
		while (!terminate) {
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				logger.warn(e);
			}
		}
	}

	public void terminate() {
		terminate = true;
		J2735.deinitialize();
		try {
			if (wsServer != null)
				wsServer.stop();
		} catch (Exception e) {
			logger.error("Failed to stop WebSocket Server", e);
		}
		MessageCounting.terminate();
	}
	
	public int getListenPort() {
		return listenPort;
	}

	@UserConfigured(value="80", description="The port the WebSocket Server will listen on.")
	public void setListenPort(int listenPort) {
		this.listenPort = listenPort;
	}

	public boolean isSecure() {
		return secure;
	}

	@UserConfigured(value="false",
			description = "Specifies whether or not to use secure WebSockets (WSS via SSL/TLS).",
			flexValidator={"RegExpValidator expression=^(true|false)$"})
	public void setSecure(boolean secure) {
		this.secure = secure;
	}

	public String getKeystorePath() {
		return keystorePath;
	}

	@UserConfigured(
			value = "/usr/local/rtws/transport/conf/keystore", 
			description = "Absolute path of the Transport keystore file.")
	public void setKeystorePath(String keystorePath) {
		this.keystorePath = keystorePath;
	}

	public String getKeystorePassword() {
		return keystorePassword;
	}

	@UserConfigured(value="", description="The password for the Transport keystore.")
	public void setKeystorePassword(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}
	
	@UserConfigured(value = "1000")
	public void setMaxTimeBetweenFlush(int value) {
		bundler.setFlushInterval(value);
	}
	
	@UserConfigured(value = "true")
	public void setLowVolumeFlushStrategy(boolean lowVolumeFlushStrategy) {
		bundler.setLowVolumeFlushStrategy(lowVolumeFlushStrategy);
	}
	
}

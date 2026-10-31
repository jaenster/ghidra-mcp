package com.ghidramcp;

import ghidra.framework.client.NotConnectedException;

import java.rmi.ConnectIOException;
import java.rmi.NoSuchObjectException;
import java.rmi.RemoteException;
import java.rmi.ServerError;
import java.rmi.ServerException;

/**
 * Tells a lost Ghidra Server connection apart from an ordinary command failure.
 *
 * A restarted server forgets every RMI object it exported, so each stub a worker holds -
 * the server handle, the repository handle, the buffer file a read-only program pages
 * from - answers with NoSuchObjectException from then on, and Ghidra's own adapters,
 * once they notice, answer NotConnectedException. Neither heals on its own.
 */
public final class ServerConnection {
    /** Prefix on every error that means "the server connection is gone", for the daemon and gateway. */
    public static final String UNAVAILABLE = "ghidra_server_unavailable";

    private ServerConnection() {}

    /** A failure caused by the server connection rather than by the command. */
    public static boolean isLoss(Throwable t) {
        for (Throwable c : chain(t)) {
            if (c instanceof ServerUnavailableException
                    || c instanceof NotConnectedException
                    || c instanceof NoSuchObjectException
                    || c instanceof ConnectIOException
                    || c instanceof java.rmi.ConnectException
                    || c instanceof java.net.ConnectException) {
                return true;
            }
            // A ServerException carries an exception the server raised while running the
            // call, so the connection worked; any other RemoteException is the transport.
            if (c instanceof RemoteException && !(c instanceof ServerException) && !(c instanceof ServerError)) {
                return true;
            }
            String m = c.getMessage();
            if (m != null && (m.contains("Not connected to repository server")
                    || m.contains("no such object in table")
                    || m.contains("(not connected)"))) {
                return true;
            }
        }
        return false;
    }

    /**
     * A loss where the call cannot have reached a live server object, so running it again
     * after reconnecting does not repeat anything. Only these let a write be retried.
     */
    public static boolean isRetrySafe(Throwable t) {
        for (Throwable c : chain(t)) {
            if (c instanceof NotConnectedException
                    || c instanceof NoSuchObjectException
                    || c instanceof ConnectIOException
                    || c instanceof java.rmi.ConnectException
                    || c instanceof java.net.ConnectException) {
                return true;
            }
            String m = c.getMessage();
            if (m != null && (m.contains("Not connected to repository server")
                    || m.contains("no such object in table")
                    || m.contains("(not connected)"))) {
                return true;
            }
        }
        return false;
    }

    /** The innermost message, which names the actual transport failure. */
    public static String describe(Throwable t) {
        java.util.List<Throwable> all = chain(t);
        Throwable last = all.isEmpty() ? t : all.get(all.size() - 1);
        String m = last.getMessage();
        return last.getClass().getSimpleName() + (m != null ? ": " + m : "");
    }

    /** The cause chain, outermost first, cut short of cycles. */
    private static java.util.List<Throwable> chain(Throwable t) {
        java.util.List<Throwable> out = new java.util.ArrayList<>();
        for (Throwable c = t; c != null && out.size() < 32 && !out.contains(c); c = c.getCause()) {
            out.add(c);
        }
        return out;
    }

    /** The connection to the Ghidra Server is down and could not be restored for this call. */
    public static final class ServerUnavailableException extends Exception {
        public ServerUnavailableException(String detail, Throwable cause) {
            super(UNAVAILABLE + ": " + detail, cause);
        }
    }
}

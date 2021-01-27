package eu.siacs.conversations.utils;

import android.content.ContentValues;
import android.database.Cursor;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.List;

import de.measite.minidns.AbstractDNSClient;
import de.measite.minidns.DNSClient;
import de.measite.minidns.DNSName;
import de.measite.minidns.Question;
import de.measite.minidns.Record;
import de.measite.minidns.dnssec.DNSSECResultNotAuthenticException;
import de.measite.minidns.dnsserverlookup.AndroidUsingExec;
import de.measite.minidns.hla.DnssecResolverApi;
import de.measite.minidns.hla.ResolverApi;
import de.measite.minidns.hla.ResolverResult;
import de.measite.minidns.iterative.ReliableDNSClient;
import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.CNAME;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.InternetAddressRR;
import de.measite.minidns.record.SRV;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.R;
import eu.siacs.conversations.persistance.FileBackend;
import eu.siacs.conversations.services.XmppConnectionService;

public class Resolver {

    public static final int DEFAULT_PORT_XMPP = 5222;

    private static final String DIRECT_TLS_SERVICE = "_xmpps-client";
    private static final String STARTTLS_SERVICE = "_xmpp-client";

    private static XmppConnectionService SERVICE = null;


    public static void init(XmppConnectionService service) {
        Resolver.SERVICE = service;
        DNSClient.removeDNSServerLookupMechanism(AndroidUsingExec.INSTANCE);
        DNSClient.addDnsServerLookupMechanism(AndroidUsingExecLowPriority.INSTANCE);
        DNSClient.addDnsServerLookupMechanism(new AndroidUsingLinkProperties(service));
        final AbstractDNSClient client = ResolverApi.INSTANCE.getClient();
        if (client instanceof ReliableDNSClient) {
            disableHardcodedDnsServers((ReliableDNSClient) client);
        }
    }

    private static void disableHardcodedDnsServers(ReliableDNSClient reliableDNSClient) {
        try {
            final Field dnsClientField = ReliableDNSClient.class.getDeclaredField("dnsClient");
            dnsClientField.setAccessible(true);
            final DNSClient dnsClient = (DNSClient) dnsClientField.get(reliableDNSClient);
            if (dnsClient != null) {
                dnsClient.getDataSource().setTimeout(3000);
            }
            final Field useHardcodedDnsServers = DNSClient.class.getDeclaredField("useHardcodedDnsServers");
            useHardcodedDnsServers.setAccessible(true);
            useHardcodedDnsServers.setBoolean(dnsClient, false);
        } catch (NoSuchFieldException e) {
            Log.e(Config.LOGTAG, "Unable to disable hardcoded DNS servers", e);
        } catch (IllegalAccessException e) {
            Log.e(Config.LOGTAG, "Unable to disable hardcoded DNS servers", e);
        }
    }

    public static Result fromHardCoded(final String hostname, final int port) {
        final Result ipResult = fromIpAddress(hostname, port);
        if (ipResult != null) {
            ipResult.connect();
            return ipResult;
        }
        return happyEyeball(resolveNoSrvRecords(DNSName.from(hostname), port, true));
    }

    public static boolean useDirectTls(final int port) {
        return port == 443 || port == 5223;
    }

    public static boolean invalidHostname(final String hostname) {
        try {
            DNSName.from(hostname);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    public static Result resolve(String domain) {
        final Result ipResult = fromIpAddress(domain, DEFAULT_PORT_XMPP);
        if (ipResult != null) {
            ipResult.connect();
            return ipResult;
        }
        final List<Result> results = new ArrayList<>();
        final List<Result> fallbackResults = new ArrayList<>();
        Thread[] threads = new Thread[3];
        threads[0] = new Thread(() -> {
            try {
                final List<Result> list = resolveSrv(domain, true);
                synchronized (results) {
                    results.addAll(list);
                }
            } catch (Throwable throwable) {
                Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": error resolving SRV record (direct TLS)", throwable);
            }
        });
        threads[1] = new Thread(() -> {
            try {
                final List<Result> list = resolveSrv(domain, false);
                synchronized (results) {
                    results.addAll(list);
                }
            } catch (Throwable throwable) {
                Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": error resolving SRV record (STARTTLS)", throwable);
            }
        });
        threads[2] = new Thread(() -> {
            List<Result> list = resolveNoSrvRecords(DNSName.from(domain), DEFAULT_PORT_XMPP, true);
            synchronized (fallbackResults) {
                fallbackResults.addAll(list);
            }
        });
        for (Thread thread : threads) {
            thread.start();
        }
        try {
            threads[0].join();
            threads[1].join();
            if (results.size() > 0) {
                threads[2].interrupt();
                synchronized (results) {
                    Collections.sort(results);
                    return happyEyeball(results);
                }
            } else {
                threads[2].join();
                synchronized (fallbackResults) {
                    Collections.sort(fallbackResults);
                    return happyEyeball(fallbackResults);
                }
            }
        } catch (InterruptedException e) {
            for (Thread thread : threads) {
                thread.interrupt();
            }
            return null;
        }
    }

    private static Result fromIpAddress(String domain, int port) {
        if (!IP.matches(domain)) {
            return null;
        }
        try {
            Result result = new Result();
            result.ip = InetAddress.getByName(domain);
            result.hostname = DNSName.from(domain);
            result.port = port;
            result.authenticated = true;
            return result;
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static List<Result> resolveSrv(String domain, final boolean directTls) throws IOException {
        DNSName dnsName = DNSName.from((directTls ? DIRECT_TLS_SERVICE : STARTTLS_SERVICE) + "._tcp." + domain);
        ResolverResult<SRV> result = resolveWithFallback(dnsName, SRV.class);
        final List<Result> results = new ArrayList<>();
        final List<Thread> threads = new ArrayList<>();

        final List<Result> fallbackResults = new ArrayList<>();
        final List<Thread> fallbackThreads = new ArrayList<>();
        for (SRV record : result.getAnswersOrEmptySet()) {
            if (record.name.length() == 0) {
                continue;
            }
            threads.add(new Thread(() -> {
                final List<Result> ipv6s = resolveIp(record, AAAA.class, result.isAuthenticData(), directTls);
                synchronized (results) {
                    results.addAll(ipv6s);
                }
            }));
            threads.add(new Thread(() -> {
                final List<Result> ipv4s = resolveIp(record, A.class, result.isAuthenticData(), directTls);
                synchronized (results) {
                    results.addAll(ipv4s);
                }
            }));
            fallbackThreads.add(new Thread(() -> {
                try {
                    ResolverResult<CNAME> cnames = resolveWithFallback(record.name, CNAME.class, result.isAuthenticData());
                    for (CNAME cname : cnames.getAnswersOrEmptySet()) {
                        final List<Result> ipv6s = resolveIp(record, cname.name, AAAA.class, cnames.isAuthenticData(), directTls);
                        synchronized (fallbackResults) {
                            fallbackResults.addAll(ipv6s);
                        }
                        final List<Result> ipv4s = resolveIp(record, cname.name, A.class, cnames.isAuthenticData(), directTls);
                        synchronized (results) {
                            fallbackResults.addAll(ipv4s);
                        }
                    }
                    Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + "cname in srv (agains RFC2782) - run slow fallback");
                } catch (Throwable throwable) {
                    Log.i(Config.LOGTAG, Resolver.class.getSimpleName() + "error resolving srv cname-fallback records", throwable);
                }
            }));
        }
        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                return Collections.emptyList();
            }
        }
        if (results.size() > 0) {
            return results;
        }

        for (Thread thread : fallbackThreads) {
            thread.start();
        }
        for (Thread thread : fallbackThreads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                return Collections.emptyList();
            }
        }
        return fallbackResults;
    }

    private static <D extends InternetAddressRR> List<Result> resolveIp(SRV srv, Class<D> type, boolean authenticated, boolean directTls) {
        return resolveIp(srv, srv.name, type, authenticated, directTls);
    }
    private static <D extends InternetAddressRR> List<Result> resolveIp(SRV srv, DNSName hostname, Class<D> type, boolean authenticated, boolean directTls) {
        List<Result> list = new ArrayList<>();
        try {
            ResolverResult<D> results = resolveWithFallback(hostname, type, authenticated);
            for (D record : results.getAnswersOrEmptySet()) {
                Result resolverResult = Result.fromRecord(srv, directTls);
                resolverResult.authenticated = results.isAuthenticData() && authenticated; //TODO technically it doesn’t matter if the IP was authenticated
                resolverResult.ip = record.getInetAddress();
                list.add(resolverResult);
            }
        } catch (Throwable t) {
            Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": error resolving " + type.getSimpleName() + " " + t.getMessage());
        }
        return list;
    }

    private static List<Result> resolveNoSrvRecords(DNSName dnsName, int port, boolean withCnames) {
        List<Result> results = new ArrayList<>();
        try {
            for (AAAA aaaa : resolveWithFallback(dnsName, AAAA.class, false).getAnswersOrEmptySet()) {
                results.add(Result.createDefault(dnsName, aaaa.getInetAddress(), port));
            }
            for (A a : resolveWithFallback(dnsName, A.class, false).getAnswersOrEmptySet()) {
                results.add(Result.createDefault(dnsName, a.getInetAddress(), port));
            }
            if (results.size() == 0 && withCnames) {
                for (CNAME cname : resolveWithFallback(dnsName, CNAME.class, false).getAnswersOrEmptySet()) {
                    results.addAll(resolveNoSrvRecords(cname.name, port, false));
                }
            }
        } catch (Throwable throwable) {
            Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + "error resolving fallback records", throwable);
        }
        return results;
    }

    private static <D extends Data> ResolverResult<D> resolveWithFallback(DNSName dnsName, Class<D> type) throws IOException {
        return resolveWithFallback(dnsName, type, validateHostname());
    }

    private static <D extends Data> ResolverResult<D> resolveWithFallback(DNSName dnsName, Class<D> type, boolean validateHostname) throws IOException {
        final Question question = new Question(dnsName, Record.TYPE.getType(type));
        if (!validateHostname) {
            return ResolverApi.INSTANCE.resolve(question);
        }
        try {
            return DnssecResolverApi.INSTANCE.resolveDnssecReliable(question);
        } catch (DNSSECResultNotAuthenticException e) {
            Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": error resolving " + type.getSimpleName() + " with DNSSEC. Trying DNS instead.", e);
        } catch (IOException e) {
            throw e;
        } catch (Throwable throwable) {
            Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": error resolving " + type.getSimpleName() + " with DNSSEC. Trying DNS instead.", throwable);
        }
        return ResolverApi.INSTANCE.resolve(question);
    }

    private static Result happyEyeball(List<Result> r) {
        String logID = Long.toHexString(Double.doubleToLongBits(Math.random()));
        Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": happy eyeball (" + logID + ") with " + r.toString());
        if (r.size() == 0) return null;

        Result result;
        if (r.size() == 1) {
            result = r.get(0);
            result.setLogID(logID);
            result.connect();
            return result;
        }

        for (Result res : r) {
            res.setLogID(logID);
        }

        ExecutorService executor = Executors.newFixedThreadPool(4);

        try {
            result = executor.invokeAny(r);
            executor.shutdown();
            Thread disconnector = new Thread(() -> {
                while (true) {
                    try {
                        if (executor.awaitTermination(5, TimeUnit.SECONDS)) break;
                        Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": happy eyeball (" + logID + ") wait for cleanup ...");
                    } catch (InterruptedException e) {}
                }
                Log.i(Config.LOGTAG, Resolver.class.getSimpleName() + ": happy eyeball (" + logID + ") cleanup");
                for (Result re : r) {
                    if(!re.equals(result)) re.disconnect();
                }
            });
            disconnector.start();
            Log.i(Config.LOGTAG, Resolver.class.getSimpleName() + ": happy eyeball (" + logID + ") used: " + result.toString());
            return result;
        } catch (InterruptedException e) {
            Log.e(Config.LOGTAG, Resolver.class.getSimpleName() + ": happy eyeball (" + logID + ") failed: ", e);
            return null;
        } catch (ExecutionException e) {
            Log.i(Config.LOGTAG, Resolver.class.getSimpleName() + ": happy eyeball (" + logID + ") unable to connect to one address");
            return null;
        }
    }

    private static boolean validateHostname() {
        return SERVICE != null && SERVICE.getBooleanPreference("validate_hostname", R.bool.validate_hostname);
    }

    public static class Result implements Comparable<Result>, Callable<Result> {
        public static final String DOMAIN = "domain";
        public static final String IP = "ip";
        public static final String HOSTNAME = "hostname";
        public static final String PORT = "port";
        public static final String PRIORITY = "priority";
        public static final String DIRECT_TLS = "directTls";
        public static final String AUTHENTICATED = "authenticated";
        public static final String TIME_REQUESTED = "time_requested";

        private InetAddress ip;
        private DNSName hostname;
        private int port = DEFAULT_PORT_XMPP;
        private boolean directTls = false;
        private boolean authenticated = false;
        private int priority;
        private long timeRequested;
        private Socket socket;

        private String logID = "";

        static Result fromRecord(SRV srv, boolean directTls) {
            Result result = new Result();
            result.timeRequested = System.currentTimeMillis();
            result.port = srv.port;
            result.hostname = srv.name;
            result.directTls = directTls;
            result.priority = srv.priority;
            return result;
        }
 
        static Result createDefault(DNSName hostname, InetAddress ip, int port) {
            Result result = new Result();
            result.timeRequested = System.currentTimeMillis();
            result.port = port;
            result.hostname = hostname;
            result.ip = ip;
            return result;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Result result = (Result) o;

            if (port != result.port) return false;
            if (directTls != result.directTls) return false;
            if (authenticated != result.authenticated) return false;
            if (priority != result.priority) return false;
            if (ip != null ? !ip.equals(result.ip) : result.ip != null) return false;
            return hostname != null ? hostname.equals(result.hostname) : result.hostname == null;
        }

        @Override
        public int hashCode() {
            int result = ip != null ? ip.hashCode() : 0;
            result = 31 * result + (hostname != null ? hostname.hashCode() : 0);
            result = 31 * result + port;
            result = 31 * result + (directTls ? 1 : 0);
            result = 31 * result + (authenticated ? 1 : 0);
            result = 31 * result + priority;
            return result;
        }

        public DNSName getHostname() {
            return hostname;
        }

        public boolean isDirectTls() {
            return directTls;
        }

        public boolean isAuthenticated() {
            return authenticated;
        }

        public boolean isOutdated() {
            return (System.currentTimeMillis() - timeRequested) > 300_000;
        }

        public Socket getSocket() {
            return socket;
        }

        @Override
        public String toString() {
            return "Result{" +
                    "ip='" + (ip == null ? null : ip.getHostAddress()) + '\'' +
                    ", hostname='" + (hostname == null ? null : hostname.toString()) + '\'' +
                    ", port=" + port +
                    ", directTls=" + directTls +
                    ", authenticated=" + authenticated +
                    ", priority=" + priority +
                    '}';
        }

        public void connect() {
            if (this.socket != null) {
                this.disconnect();
            }
            final InetSocketAddress addr = new InetSocketAddress(this.ip, this.port);
            this.socket = new Socket();
            try {
                long time = System.currentTimeMillis();
                this.socket.connect(addr, Config.SOCKET_TIMEOUT * 1000);
                time = System.currentTimeMillis() - time;
                if (!this.logID.isEmpty()) {
                    Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": Result (" + this.logID + ") connect: " + toString() + " after: " + time + " ms");
                } else {
                    Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": Result connect: " + toString() + " after: " + time + " ms");
                }
            } catch (IOException e) {
                this.disconnect();
            }
        }

        public void disconnect() {
            if (this.socket != null ) {
                FileBackend.close(this.socket);
                this.socket = null;
                if (!this.logID.isEmpty()) {
                    Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": Result (" + this.logID + ") disconnect: " + toString());
                } else {
                    Log.d(Config.LOGTAG, Resolver.class.getSimpleName() + ": Result disconnect: " + toString());
                }
            }
        }

        public void setLogID(String logID) {
            this.logID = logID;
        }

        @Override
        public int compareTo(@NonNull Result result) {
            if (result.priority == priority) {
                if (directTls == result.directTls) {
                    return 0;
                } else {
                    return directTls ? -1 : 1;
                }
            } else {
                return priority - result.priority;
            }
        }
        @Override
        public Result call() throws Exception {
            this.connect();
            if (this.socket != null && this.socket.isConnected()) {
                return this;
            }
            throw new Exception("Resolver.Result was not possible to connect - should be catched by executor");
        }

        public static Result fromCursor(Cursor cursor) {
            final Result result = new Result();
            try {
                result.ip = InetAddress.getByAddress(cursor.getBlob(cursor.getColumnIndex(IP)));
            } catch (UnknownHostException e) {
                result.ip = null;
            }
            final String hostname = cursor.getString(cursor.getColumnIndex(HOSTNAME));
            result.hostname = hostname == null ? null : DNSName.from(hostname);
            result.port = cursor.getInt(cursor.getColumnIndex(PORT));
            result.directTls = cursor.getInt(cursor.getColumnIndex(DIRECT_TLS)) > 0;
            result.authenticated = cursor.getInt(cursor.getColumnIndex(AUTHENTICATED)) > 0;
            result.priority = cursor.getInt(cursor.getColumnIndex(PRIORITY));
            result.timeRequested = cursor.getLong(cursor.getColumnIndex(TIME_REQUESTED));
            return result;
        }


        public ContentValues toContentValues() {
            final ContentValues contentValues = new ContentValues();
            contentValues.put(IP, ip == null ? null : ip.getAddress());
            contentValues.put(HOSTNAME, hostname == null ? null : hostname.toString());
            contentValues.put(PORT, port);
            contentValues.put(PRIORITY, priority);
            contentValues.put(DIRECT_TLS, directTls ? 1 : 0);
            contentValues.put(AUTHENTICATED, authenticated ? 1 : 0);
            contentValues.put(TIME_REQUESTED, timeRequested);
            return contentValues;
        }
    }

}

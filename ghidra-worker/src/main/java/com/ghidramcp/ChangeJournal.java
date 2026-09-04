package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.EventType;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.model.TransactionListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.FunctionChangeRecord;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * An ordered, durable journal of program changes.
 *
 * This replaces the old set-based DirtyTracker. A set can answer "what is dirty now" and
 * nothing else: it cannot be shared by two consumers (one mark_clean erases the other's
 * work), it cannot be resumed after a disconnect, and it loses the order in which things
 * happened. A live consumer - the reconstruction daemon - needs all three.
 *
 * Each batch of Ghidra change records becomes a run of events with strictly increasing
 * sequence numbers, appended to NDJSON on the project directory and pushed to the daemon.
 * A consumer that has seen up to sequence N asks for everything after N and is exactly
 * caught up, whether it was gone for a second or for a day.
 *
 * <h2>Delivery is on a timer, not on commit</h2>
 *
 * Ghidra does not deliver change records when a transaction ends. {@code endTransaction}
 * only schedules a flush, and {@code DomainObjectChangeSupport} runs it on a 500 ms timer,
 * so a read issued immediately after a write can legitimately observe no event yet. That
 * timing - not a gap in what is being listened to - is why the old tracker appeared to
 * "miss" struct-field and variable retypes. The fix belongs at the call site: flush the
 * program's events after a write completes, and report the resulting sequence number with
 * the write, so a caller can wait for exactly its own change. See CommandDispatcher.
 *
 * <h2>Transaction stamping is best effort</h2>
 *
 * Because the flush is on a timer it may coalesce several transactions into one batch.
 * The transaction id and description recorded on an event are those of the most recently
 * ENDED transaction at flush time, which is right in the common case (one write, one
 * transaction, one flush) and approximate under load. Never use it for ordering - that is
 * what {@code seq} is for.
 */
public class ChangeJournal implements DomainObjectListener, TransactionListener {

    /** Kinds are a closed set; consumers switch on them. */
    public static final String KIND_FUNCTION_CHANGED = "function.changed";
    public static final String KIND_FUNCTION_BODY = "function.body";
    public static final String KIND_FUNCTION_SIGNATURE = "function.signature";
    public static final String KIND_SYMBOL_RENAMED = "symbol.renamed";
    public static final String KIND_DATATYPE_CHANGED = "datatype.changed";
    public static final String KIND_DATATYPE_RENAMED = "datatype.renamed";
    public static final String KIND_DATATYPE_REPLACED = "datatype.replaced";
    public static final String KIND_DATATYPE_ADDED = "datatype.added";
    public static final String KIND_DATATYPE_REMOVED = "datatype.removed";
    public static final String KIND_DATA_CHANGED = "data.changed";
    public static final String KIND_REF_ADDED = "ref.added";
    public static final String KIND_REF_REMOVED = "ref.removed";
    public static final String KIND_CODE_ADDED = "code.added";
    public static final String KIND_CODE_REMOVED = "code.removed";
    public static final String KIND_RESTORED = "restored";

    /** Targets say which index of the consumer's model a key addresses. */
    public static final String TARGET_FUNCTION = "function";
    public static final String TARGET_GLOBAL = "global";
    public static final String TARGET_DATATYPE = "datatype";
    public static final String TARGET_PROGRAM = "program";

    private static final long ROTATE_BYTES = 50L * 1024 * 1024;

    /** One journal entry. Field names are the wire format - see protocol.ts ChangeEvent. */
    public static class ChangeEvent {
        public long seq;
        public long mod;
        public long ts;
        public String kind;
        public String target;
        public String key;
        public String oldName;
        public String newName;
        public Long txId;
        public String txDescription;
    }

    private final Logger log;
    private final Gson gson = new Gson();

    private Program program;
    private Path journalPath;
    private long seq = 0;

    /** Most recently ended transaction, used to stamp the next flushed batch. */
    private volatile long lastTxId = -1;
    private volatile String lastTxDescription = null;

    private volatile Consumer<List<ChangeEvent>> batchListener;

    public ChangeJournal(Logger log) {
        this.log = log;
    }

    public void attach(Program program) {
        this.program = program;
        this.journalPath = resolveJournalPath(program);
        this.seq = readTailSeq();
        program.addListener(this);
        if (program instanceof DomainObjectAdapterDB db) {
            db.addTransactionListener(this);
        }
        log.info("ChangeJournal attached to " + program.getName() + " at seq " + seq
            + " (" + journalPath + ")");
    }

    public void detach() {
        if (program == null) return;
        program.removeListener(this);
        if (program instanceof DomainObjectAdapterDB db) {
            db.removeTransactionListener(this);
        }
        log.info("ChangeJournal detached from " + program.getName() + " at seq " + seq);
        program = null;
    }

    /** Called with each appended batch, in order. Used to push to the daemon. */
    public void setBatchListener(Consumer<List<ChangeEvent>> listener) {
        this.batchListener = listener;
    }

    /** The highest sequence number written. A consumer resumes from here. */
    public synchronized long head() {
        return seq;
    }

    // ============== Listening ==============

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        if (program == null) return;

        // Dedup within the batch, keeping first-seen order: a hundred field edits in one
        // transaction are one datatype.changed, which is what a consumer would collapse
        // them to anyway. Ordering across batches is what carries meaning.
        Map<String, ChangeEvent> batch = new LinkedHashMap<>();

        for (int i = 0; i < ev.numRecords(); i++) {
            var rec = ev.getChangeRecord(i);
            EventType type = rec.getEventType();

            if (type == DomainObjectEvent.RESTORED) {
                // Undo, redo or a re-read from disk. Nothing says WHAT moved, so a
                // consumer has no option but to resynchronise from scratch.
                put(batch, KIND_RESTORED, TARGET_PROGRAM, "*", null, null);
                continue;
            }

            if (!(rec instanceof ProgramChangeRecord pcr)) continue;

            if (type == ProgramEvent.FUNCTION_CHANGED || type == ProgramEvent.FUNCTION_BODY_CHANGED) {
                recordFunctionChange(batch, pcr, type);
            } else if (type == ProgramEvent.CODE_ADDED || type == ProgramEvent.CODE_REPLACED) {
                recordAtAddress(batch, pcr.getStart(), KIND_CODE_ADDED);
            } else if (type == ProgramEvent.CODE_REMOVED) {
                recordAtAddress(batch, pcr.getStart(), KIND_CODE_REMOVED);
            } else if (type == ProgramEvent.SYMBOL_RENAMED) {
                recordSymbolRename(batch, pcr);
            } else if (type == ProgramEvent.SYMBOL_ADDED
                || type == ProgramEvent.SYMBOL_REMOVED
                || type == ProgramEvent.SYMBOL_DATA_CHANGED) {
                recordSymbolTouched(batch, pcr);
            } else if (type == ProgramEvent.DATA_TYPE_CHANGED
                || type == ProgramEvent.DATA_TYPE_SETTING_CHANGED) {
                recordDataType(batch, pcr, KIND_DATATYPE_CHANGED);
            } else if (type == ProgramEvent.DATA_TYPE_RENAMED || type == ProgramEvent.DATA_TYPE_MOVED) {
                recordDataType(batch, pcr, KIND_DATATYPE_RENAMED);
            } else if (type == ProgramEvent.DATA_TYPE_REPLACED) {
                recordDataType(batch, pcr, KIND_DATATYPE_REPLACED);
            } else if (type == ProgramEvent.DATA_TYPE_ADDED) {
                recordDataType(batch, pcr, KIND_DATATYPE_ADDED);
            } else if (type == ProgramEvent.DATA_TYPE_REMOVED) {
                recordDataType(batch, pcr, KIND_DATATYPE_REMOVED);
            } else if (type == ProgramEvent.REFERENCE_ADDED
                || type == ProgramEvent.VARIABLE_REFERENCE_ADDED) {
                recordAtAddress(batch, pcr.getStart(), KIND_REF_ADDED);
            } else if (type == ProgramEvent.REFERENCE_REMOVED
                || type == ProgramEvent.VARIABLE_REFERENCE_REMOVED) {
                recordAtAddress(batch, pcr.getStart(), KIND_REF_REMOVED);
            }
        }

        if (!batch.isEmpty()) {
            append(new ArrayList<>(batch.values()));
        }
    }

    @Override
    public void transactionStarted(DomainObjectAdapterDB obj, TransactionInfo tx) {
        if (tx == null) return;
        lastTxId = tx.getID();
        lastTxDescription = tx.getDescription();
    }

    @Override
    public void transactionEnded(DomainObjectAdapterDB obj) {
        // Keep the last started transaction's identity for the flush that follows.
    }

    @Override
    public void undoStackChanged(DomainObjectAdapterDB obj) {
    }

    @Override
    public void undoRedoOccurred(DomainObjectAdapterDB obj) {
        // RESTORED usually arrives through domainObjectChanged as well, and the batch
        // dedup collapses the pair. Recording it here too means an undo is never silent.
        Map<String, ChangeEvent> batch = new LinkedHashMap<>();
        put(batch, KIND_RESTORED, TARGET_PROGRAM, "*", null, null);
        append(new ArrayList<>(batch.values()));
    }

    // ============== Record shaping ==============

    private void recordFunctionChange(Map<String, ChangeEvent> batch, ProgramChangeRecord pcr,
                                      EventType type) {
        Function func = null;
        boolean signature = false;

        if (pcr instanceof FunctionChangeRecord fcr) {
            func = fcr.getFunction();
            signature = fcr.isFunctionSignatureChange();
        }
        if (func == null && pcr.getObject() instanceof Function f) {
            func = f;
        }
        if (func == null && pcr.getStart() != null) {
            func = program.getFunctionManager().getFunctionContaining(pcr.getStart());
        }
        if (func == null) return;

        String kind = type == ProgramEvent.FUNCTION_BODY_CHANGED
            ? KIND_FUNCTION_BODY
            : (signature ? KIND_FUNCTION_SIGNATURE : KIND_FUNCTION_CHANGED);

        put(batch, kind, TARGET_FUNCTION, func.getEntryPoint().toString(), null, null);
    }

    /**
     * Attribute an address-carrying change to its containing function, or to the address
     * itself when it lies outside one. A consumer keyed by function entry point and by
     * global address can then look the key up directly, with no second round trip.
     */
    private void recordAtAddress(Map<String, ChangeEvent> batch, Address addr, String kind) {
        if (addr == null) return;
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            put(batch, kind, TARGET_FUNCTION, func.getEntryPoint().toString(), null, null);
        } else {
            put(batch, kind, TARGET_GLOBAL, addr.toString(), null, null);
        }
    }

    private void recordSymbolRename(Map<String, ChangeEvent> batch, ProgramChangeRecord pcr) {
        String oldName = pcr.getOldValue() instanceof String s ? s : null;
        String newName = pcr.getNewValue() instanceof String s ? s : null;

        if (pcr.getObject() instanceof Symbol sym) {
            String[] tk = classifySymbol(sym);
            if (tk != null) {
                put(batch, KIND_SYMBOL_RENAMED, tk[0], tk[1], oldName, newName);
            }
            return;
        }
        recordAtAddress(batch, pcr.getStart(), KIND_SYMBOL_RENAMED);
    }

    private void recordSymbolTouched(Map<String, ChangeEvent> batch, ProgramChangeRecord pcr) {
        if (pcr.getObject() instanceof Symbol sym) {
            String[] tk = classifySymbol(sym);
            if (tk != null) {
                String kind = TARGET_FUNCTION.equals(tk[0]) ? KIND_FUNCTION_CHANGED : KIND_DATA_CHANGED;
                put(batch, kind, tk[0], tk[1], null, null);
            }
            return;
        }
        recordAtAddress(batch, pcr.getStart(), KIND_DATA_CHANGED);
    }

    /**
     * Resolve a symbol to {target, key}. Parameters and locals live in a function's
     * namespace at stack or register addresses that mean nothing to a consumer, so they
     * roll up to the function that owns them - the unit that will be re-extracted anyway.
     */
    private String[] classifySymbol(Symbol sym) {
        if (sym.getParentNamespace() instanceof Function parent) {
            return new String[] { TARGET_FUNCTION, parent.getEntryPoint().toString() };
        }
        Address addr = sym.getAddress();
        if (addr == null) return null;

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        if (func != null) {
            return new String[] { TARGET_FUNCTION, func.getEntryPoint().toString() };
        }
        return new String[] { TARGET_GLOBAL, addr.toString() };
    }

    private void recordDataType(Map<String, ChangeEvent> batch, ProgramChangeRecord pcr, String kind) {
        String oldName = null;
        String path = null;

        if (pcr.getNewValue() instanceof DataType dt) {
            path = dt.getPathName();
        } else if (pcr.getObject() instanceof DataType dt) {
            path = dt.getPathName();
        }
        if (pcr.getOldValue() instanceof DataType odt) {
            oldName = odt.getPathName();
            if (path == null) path = odt.getPathName();
        } else if (pcr.getOldValue() instanceof String s) {
            oldName = s;
        }
        if (path == null) return;

        put(batch, kind, TARGET_DATATYPE, path, oldName, path);
    }

    private void put(Map<String, ChangeEvent> batch, String kind, String target, String key,
                     String oldName, String newName) {
        ChangeEvent e = new ChangeEvent();
        e.kind = kind;
        e.target = target;
        e.key = key;
        e.oldName = oldName;
        e.newName = newName;
        // First write wins on the coalescing key, except that a later record carrying
        // names beats an earlier one that carried none - a rename is more informative
        // than the bare "something about this symbol changed" that precedes it.
        ChangeEvent existing = batch.get(kind + " " + key);
        if (existing != null && (oldName == null && newName == null)) return;
        batch.put(kind + " " + key, e);
    }

    // ============== Append ==============

    private synchronized void append(List<ChangeEvent> events) {
        if (events.isEmpty() || journalPath == null) return;

        long mod = program != null ? program.getModificationNumber() : 0;
        long now = System.currentTimeMillis();
        long txId = lastTxId;
        String txDesc = lastTxDescription;

        StringBuilder sb = new StringBuilder();
        for (ChangeEvent e : events) {
            e.seq = ++seq;
            e.mod = mod;
            e.ts = now;
            if (txId >= 0) {
                e.txId = txId;
                e.txDescription = txDesc;
            }
            sb.append(gson.toJson(e)).append('\n');
        }

        try {
            Files.createDirectories(journalPath.getParent());
            rotateIfNeeded();
            // fsync per batch: a consumer that has been told a sequence exists must find
            // it there after a crash, or resume silently skips those changes.
            try (RandomAccessFile raf = new RandomAccessFile(journalPath.toFile(), "rwd")) {
                raf.seek(raf.length());
                raf.write(sb.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException ex) {
            log.warn("ChangeJournal append failed: " + ex.getMessage());
        }

        Consumer<List<ChangeEvent>> listener = batchListener;
        if (listener != null) {
            try {
                listener.accept(events);
            } catch (Exception ex) {
                log.warn("ChangeJournal batch listener failed: " + ex.getMessage());
            }
        }
    }

    private void rotateIfNeeded() throws IOException {
        if (!Files.exists(journalPath) || Files.size(journalPath) < ROTATE_BYTES) return;
        Path rotated = journalPath.resolveSibling(journalPath.getFileName() + ".1");
        Files.move(journalPath, rotated, StandardCopyOption.REPLACE_EXISTING);
        log.info("ChangeJournal rotated at seq " + seq);
    }

    // ============== Read ==============

    /**
     * Events with {@code seq > since}, oldest first, at most {@code limit}. Reads the
     * rotated file first so a consumer that fell behind a rotation still gets order.
     */
    public synchronized List<JsonObject> read(long since, int limit) {
        List<JsonObject> out = new ArrayList<>();
        if (journalPath == null) return out;

        Path rotated = journalPath.resolveSibling(journalPath.getFileName() + ".1");
        for (Path p : List.of(rotated, journalPath)) {
            if (out.size() >= limit) break;
            if (!Files.exists(p)) continue;
            try (var lines = Files.lines(p, StandardCharsets.UTF_8)) {
                for (String line : (Iterable<String>) lines::iterator) {
                    if (line.isBlank()) continue;
                    JsonObject o;
                    try {
                        o = gson.fromJson(line, JsonObject.class);
                    } catch (Exception ignored) {
                        continue; // a torn last line from a hard kill
                    }
                    if (o == null || !o.has("seq")) continue;
                    if (o.get("seq").getAsLong() <= since) continue;
                    out.add(o);
                    if (out.size() >= limit) break;
                }
            } catch (IOException ex) {
                log.warn("ChangeJournal read failed: " + ex.getMessage());
            }
        }
        return out;
    }

    /**
     * Restore the sequence counter from the journal. Sequence numbers must never repeat
     * across a restart: a consumer holding seq N would silently skip the reused numbers.
     */
    private long readTailSeq() {
        if (journalPath == null || !Files.exists(journalPath)) return 0;
        long max = 0;
        try (var lines = Files.lines(journalPath, StandardCharsets.UTF_8)) {
            for (String line : (Iterable<String>) lines::iterator) {
                if (line.isBlank()) continue;
                try {
                    JsonObject o = gson.fromJson(line, JsonObject.class);
                    if (o != null && o.has("seq")) {
                        max = Math.max(max, o.get("seq").getAsLong());
                    }
                } catch (Exception ignored) {
                    // torn line
                }
            }
        } catch (IOException ex) {
            log.warn("ChangeJournal could not read tail sequence: " + ex.getMessage());
        }
        return max;
    }

    private Path resolveJournalPath(Program program) {
        try {
            var dir = program.getDomainFile().getProjectLocator().getProjectDir().getAbsolutePath();
            return Paths.get(dir).resolve(".ghidra-mcp")
                .resolve("changes-" + program.getName() + ".ndjson");
        } catch (Exception ex) {
            log.warn("ChangeJournal has no project dir, journal disabled: " + ex.getMessage());
            return null;
        }
    }
}

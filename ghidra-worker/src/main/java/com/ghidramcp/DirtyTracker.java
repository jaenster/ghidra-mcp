package com.ghidramcp;

import com.ghidramcp.logging.Logger;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.EventType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.FunctionChangeRecord;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks Ghidra program changes since the last clean mark.
 * Implements DomainObjectListener to receive change events from the program.
 *
 * Dirty state is persisted to disk so it survives worker restarts.
 */
public class DirtyTracker implements DomainObjectListener {

    private final Set<String> dirtyFunctions = ConcurrentHashMap.newKeySet();
    private final Set<String> dirtyDataTypes = ConcurrentHashMap.newKeySet();
    private final Set<String> dirtyGlobals = ConcurrentHashMap.newKeySet();
    private long lastCleanVersion = 0;
    private Program program;
    private final Logger log;

    // Debounce persistence: track last save time to avoid thrashing
    private long lastSaveTimeMs = 0;
    private static final long SAVE_DEBOUNCE_MS = 1000;

    public DirtyTracker(Logger log) {
        this.log = log;
    }

    public void attach(Program program) {
        this.program = program;
        program.addListener(this);
        this.lastCleanVersion = program.getModificationNumber();
        log.info("DirtyTracker attached to " + program.getName() + " at version " + lastCleanVersion);
    }

    public void detach() {
        if (program != null) {
            program.removeListener(this);
            log.info("DirtyTracker detached from " + program.getName());
            program = null;
        }
    }

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        boolean changed = false;

        for (int i = 0; i < ev.numRecords(); i++) {
            var rec = ev.getChangeRecord(i);
            EventType eventType = rec.getEventType();

            if (!(rec instanceof ProgramChangeRecord pcr)) continue;

            // Function changes — variable type/storage/signature changes arrive here as
            // FunctionChangeRecord (subclass of ProgramChangeRecord) with getFunction().
            if (eventType == ProgramEvent.FUNCTION_CHANGED
                || eventType == ProgramEvent.FUNCTION_BODY_CHANGED) {
                Function func = null;
                if (rec instanceof FunctionChangeRecord fcr) {
                    func = fcr.getFunction();
                }
                if (func == null) {
                    Object obj = pcr.getObject();
                    if (obj instanceof Function f) func = f;
                }
                if (func == null && pcr.getStart() != null && program != null) {
                    func = program.getFunctionManager().getFunctionContaining(pcr.getStart());
                }
                if (func != null) {
                    dirtyFunctions.add(func.getEntryPoint().toString());
                    changed = true;
                }
            }

            // Code changes — find affected functions
            if (eventType == ProgramEvent.CODE_ADDED
                || eventType == ProgramEvent.CODE_REMOVED
                || eventType == ProgramEvent.CODE_REPLACED) {
                var start = pcr.getStart();
                if (start != null && program != null) {
                    Function func = program.getFunctionManager().getFunctionContaining(start);
                    if (func != null) {
                        dirtyFunctions.add(func.getEntryPoint().toString());
                        changed = true;
                    }
                }
            }

            // Symbol renames
            if (eventType == ProgramEvent.SYMBOL_RENAMED
                || eventType == ProgramEvent.SYMBOL_DATA_CHANGED) {
                Object obj = pcr.getObject();
                if (obj instanceof Symbol sym) {
                    classifySymbolChange(sym);
                    changed = true;
                }
            }

            // Data type changes
            if (eventType == ProgramEvent.DATA_TYPE_CHANGED
                || eventType == ProgramEvent.DATA_TYPE_REPLACED
                || eventType == ProgramEvent.DATA_TYPE_RENAMED) {
                Object obj = pcr.getNewValue();
                if (obj instanceof ghidra.program.model.data.DataType dt) {
                    dirtyDataTypes.add(dt.getPathName());
                    changed = true;
                } else {
                    obj = pcr.getObject();
                    if (obj instanceof ghidra.program.model.data.DataType dt) {
                        dirtyDataTypes.add(dt.getPathName());
                        changed = true;
                    }
                }
            }

            // Reference changes — find affected functions
            if (eventType == ProgramEvent.REFERENCE_ADDED
                || eventType == ProgramEvent.REFERENCE_REMOVED
                || eventType == ProgramEvent.VARIABLE_REFERENCE_ADDED
                || eventType == ProgramEvent.VARIABLE_REFERENCE_REMOVED) {
                var start = pcr.getStart();
                if (start != null && program != null) {
                    Function func = program.getFunctionManager().getFunctionContaining(start);
                    if (func != null) {
                        dirtyFunctions.add(func.getEntryPoint().toString());
                        changed = true;
                    }
                }
            }
        }

        if (changed) {
            debouncedSave();
        }
    }

    private void classifySymbolChange(Symbol sym) {
        if (program == null) return;

        // Parameter and local-variable symbols live in a function's namespace but have
        // non-memory addresses (stack/register space). Check parent namespace first.
        var ns = sym.getParentNamespace();
        if (ns instanceof Function parentFunc) {
            dirtyFunctions.add(parentFunc.getEntryPoint().toString());
            return;
        }

        var addr = sym.getAddress();
        if (addr == null) return;

        // Check if it's a function entry point symbol
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func != null) {
            dirtyFunctions.add(func.getEntryPoint().toString());
            return;
        }

        // Check if it's inside a function body
        func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            dirtyFunctions.add(func.getEntryPoint().toString());
            return;
        }

        // Otherwise treat as global
        dirtyGlobals.add(addr.toString());
    }

    // ============== Query ==============

    public Set<String> getDirtyFunctions() { return Collections.unmodifiableSet(new HashSet<>(dirtyFunctions)); }
    public Set<String> getDirtyDataTypes() { return Collections.unmodifiableSet(new HashSet<>(dirtyDataTypes)); }
    public Set<String> getDirtyGlobals() { return Collections.unmodifiableSet(new HashSet<>(dirtyGlobals)); }

    public boolean hasDirtySymbols() {
        return !dirtyFunctions.isEmpty() || !dirtyDataTypes.isEmpty() || !dirtyGlobals.isEmpty();
    }

    public JsonObject getSummaryJson() {
        JsonObject summary = new JsonObject();
        summary.addProperty("functions", dirtyFunctions.size());
        summary.addProperty("dataTypes", dirtyDataTypes.size());
        summary.addProperty("globals", dirtyGlobals.size());
        summary.addProperty("since", lastCleanVersion);
        return summary;
    }

    public JsonObject getDetailJson() {
        JsonObject detail = new JsonObject();
        JsonArray funcs = new JsonArray();
        dirtyFunctions.forEach(funcs::add);
        detail.add("functions", funcs);

        JsonArray types = new JsonArray();
        dirtyDataTypes.forEach(types::add);
        detail.add("dataTypes", types);

        JsonArray globals = new JsonArray();
        dirtyGlobals.forEach(globals::add);
        detail.add("globals", globals);

        detail.addProperty("lastCleanVersion", lastCleanVersion);
        return detail;
    }

    // ============== Clean ==============

    public void markClean() {
        dirtyFunctions.clear();
        dirtyDataTypes.clear();
        dirtyGlobals.clear();
        if (program != null) {
            lastCleanVersion = program.getModificationNumber();
        }
        // Delete persisted dirty state
        try {
            Path dirtyFile = getDirtyFilePath();
            if (dirtyFile != null) {
                Files.deleteIfExists(dirtyFile);
            }
        } catch (IOException e) {
            log.warn("Failed to delete dirty file: " + e.getMessage());
        }
        log.info("DirtyTracker marked clean at version " + lastCleanVersion);
    }

    // ============== Persistence ==============

    private void debouncedSave() {
        long now = System.currentTimeMillis();
        if (now - lastSaveTimeMs < SAVE_DEBOUNCE_MS) return;
        lastSaveTimeMs = now;
        saveToDisk();
    }

    public void saveToDisk() {
        Path dirtyFile = getDirtyFilePath();
        if (dirtyFile == null) return;

        try {
            Files.createDirectories(dirtyFile.getParent());

            JsonObject state = new JsonObject();
            state.addProperty("lastCleanVersion", lastCleanVersion);

            JsonArray funcs = new JsonArray();
            dirtyFunctions.forEach(funcs::add);
            state.add("dirtyFunctions", funcs);

            JsonArray types = new JsonArray();
            dirtyDataTypes.forEach(types::add);
            state.add("dirtyDataTypes", types);

            JsonArray globals = new JsonArray();
            dirtyGlobals.forEach(globals::add);
            state.add("dirtyGlobals", globals);

            Files.writeString(dirtyFile, new Gson().toJson(state));
        } catch (IOException e) {
            log.warn("Failed to save dirty state: " + e.getMessage());
        }
    }

    public void loadFromDisk() {
        Path dirtyFile = getDirtyFilePath();
        if (dirtyFile == null || !Files.exists(dirtyFile)) return;

        try {
            String content = Files.readString(dirtyFile);
            JsonObject state = new Gson().fromJson(content, JsonObject.class);

            lastCleanVersion = state.get("lastCleanVersion").getAsLong();

            Gson gson = new Gson();
            Type setType = new TypeToken<Set<String>>(){}.getType();

            if (state.has("dirtyFunctions")) {
                Set<String> loaded = gson.fromJson(state.get("dirtyFunctions"), setType);
                dirtyFunctions.addAll(loaded);
            }
            if (state.has("dirtyDataTypes")) {
                Set<String> loaded = gson.fromJson(state.get("dirtyDataTypes"), setType);
                dirtyDataTypes.addAll(loaded);
            }
            if (state.has("dirtyGlobals")) {
                Set<String> loaded = gson.fromJson(state.get("dirtyGlobals"), setType);
                dirtyGlobals.addAll(loaded);
            }

            log.info("DirtyTracker restored from disk: " + dirtyFunctions.size() + " functions, "
                + dirtyDataTypes.size() + " types, " + dirtyGlobals.size() + " globals");
        } catch (Exception e) {
            log.warn("Failed to load dirty state: " + e.getMessage());
        }
    }

    private Path getDirtyFilePath() {
        if (program == null) return null;
        // Use project directory's .ghidra-mcp subfolder
        var projectDir = Paths.get(program.getDomainFile().getProjectLocator().getProjectDir().getAbsolutePath());
        return projectDir.resolve(".ghidra-mcp").resolve("dirty-" + program.getName() + ".json");
    }
}

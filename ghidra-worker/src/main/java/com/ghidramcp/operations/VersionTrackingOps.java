package com.ghidramcp.operations;

import com.ghidramcp.GhidraContext;
import com.ghidramcp.logging.Logger;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.FunctionNameMarkupType;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Program;

import java.util.*;

/**
 * Version Tracking operations: create VT sessions, run correlators,
 * list/accept matches, and apply markup between two programs.
 */
public class VersionTrackingOps {
    private final GhidraContext ctx;
    private VTSessionDB vtSession;

    public VersionTrackingOps(GhidraContext ctx) {
        this.ctx = ctx;
    }

    /**
     * Create a VT session between two loaded programs.
     */
    public JsonObject createSession(String sourcePath, String destPath) throws Exception {
        Logger log = ctx.getLog();
        Program source = ctx.getPrograms().get(sourcePath);
        Program dest = ctx.getPrograms().get(destPath);

        if (source == null) throw new IllegalArgumentException("Source program not loaded: " + sourcePath);
        if (dest == null) throw new IllegalArgumentException("Destination program not loaded: " + destPath);

        // Close existing VT session if any
        if (vtSession != null) {
            try { vtSession.release(ctx); } catch (Exception e) { /* ignore */ }
        }

        vtSession = VTSessionDB.createVTSession("mcp-vt-session", source, dest, ctx);
        log.info("VT session created: " + sourcePath + " -> " + destPath);

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("sourcePath", sourcePath);
        result.addProperty("destPath", destPath);
        result.addProperty("sourceProgram", source.getName());
        result.addProperty("destProgram", dest.getName());
        return result;
    }

    /**
     * Run a correlator algorithm on the VT session.
     */
    public JsonObject runCorrelator(String correlatorName) throws Exception {
        if (vtSession == null) throw new IllegalStateException("No VT session. Call vt_create_session first.");
        Logger log = ctx.getLog();

        // Find the correlator factory
        VTAbstractProgramCorrelatorFactory factory = findFactory(correlatorName);
        if (factory == null) {
            throw new IllegalArgumentException("Unknown correlator: " + correlatorName +
                ". Use vt_get_correlators to list available correlators.");
        }

        log.info("Running correlator: " + correlatorName);
        VTProgramCorrelator correlator = factory.createCorrelator(
            vtSession.getSourceProgram(),
            vtSession.getSourceProgram().getAddressFactory().getAddressSet(
                vtSession.getSourceProgram().getMemory().getMinAddress(),
                vtSession.getSourceProgram().getMemory().getMaxAddress()),
            vtSession.getDestinationProgram(),
            vtSession.getDestinationProgram().getAddressFactory().getAddressSet(
                vtSession.getDestinationProgram().getMemory().getMinAddress(),
                vtSession.getDestinationProgram().getMemory().getMaxAddress()),
            factory.createDefaultOptions());

        int txId = vtSession.startTransaction("Run correlator: " + correlatorName);
        VTMatchSet matchSet;
        try {
            matchSet = correlator.correlate(vtSession, ctx.getMonitor());
            vtSession.endTransaction(txId, true);
        } catch (Exception e) {
            vtSession.endTransaction(txId, false);
            throw e;
        }
        log.info("Correlator complete: " + matchSet.getMatchCount() + " matches");

        JsonObject result = new JsonObject();
        result.addProperty("correlator", correlatorName);
        result.addProperty("matchCount", matchSet.getMatchCount());
        return result;
    }

    /**
     * List matches from the VT session.
     */
    public JsonObject listMatches(double minScore, int limit) throws Exception {
        if (vtSession == null) throw new IllegalStateException("No VT session.");

        JsonArray matchesArr = new JsonArray();
        int count = 0;
        int total = 0;

        for (VTMatchSet matchSet : vtSession.getMatchSets()) {
            for (VTMatch match : matchSet.getMatches()) {
                VTAssociation assoc = match.getAssociation();
                double score = match.getSimilarityScore().getScore();
                double confidence = match.getConfidenceScore().getScore();

                total++;
                if (score < minScore) continue;
                if (count >= limit) continue;

                JsonObject matchObj = new JsonObject();
                matchObj.addProperty("sourceAddress", assoc.getSourceAddress().toString());
                matchObj.addProperty("destAddress", assoc.getDestinationAddress().toString());
                matchObj.addProperty("score", score);
                matchObj.addProperty("confidence", confidence);
                matchObj.addProperty("status", assoc.getStatus().name());
                matchObj.addProperty("type", assoc.getType().name());

                // Try to get function names
                ghidra.program.model.listing.Function srcFunc =
                    vtSession.getSourceProgram().getFunctionManager()
                        .getFunctionAt(assoc.getSourceAddress());
                ghidra.program.model.listing.Function destFunc =
                    vtSession.getDestinationProgram().getFunctionManager()
                        .getFunctionAt(assoc.getDestinationAddress());

                if (srcFunc != null) matchObj.addProperty("sourceName", srcFunc.getName());
                if (destFunc != null) matchObj.addProperty("destName", destFunc.getName());

                matchesArr.add(matchObj);
                count++;
            }
        }

        JsonObject result = new JsonObject();
        result.add("matches", matchesArr);
        result.addProperty("returned", count);
        result.addProperty("total", total);
        return result;
    }

    /**
     * Accept matches by criteria.
     */
    public JsonObject acceptMatches(boolean acceptAll, double minScore) throws Exception {
        if (vtSession == null) throw new IllegalStateException("No VT session.");

        int accepted = 0;
        int txId = vtSession.startTransaction("Accept VT matches");
        try {
            for (VTMatchSet matchSet : vtSession.getMatchSets()) {
                for (VTMatch match : matchSet.getMatches()) {
                    VTAssociation assoc = match.getAssociation();
                    if (assoc.getStatus() != VTAssociationStatus.AVAILABLE) continue;

                    double score = match.getSimilarityScore().getScore();
                    if (acceptAll || score >= minScore) {
                        assoc.setAccepted();
                        accepted++;
                    }
                }
            }
            vtSession.endTransaction(txId, true);
        } catch (Exception e) {
            vtSession.endTransaction(txId, false);
            throw e;
        }

        JsonObject result = new JsonObject();
        result.addProperty("accepted", accepted);
        return result;
    }

    /**
     * Apply markup from accepted matches to the destination program.
     */
    public JsonObject applyMarkup() throws Exception {
        if (vtSession == null) throw new IllegalStateException("No VT session.");

        int applied = 0;
        int errors = 0;
        Program dest = vtSession.getDestinationProgram();
        int txId = dest.startTransaction("Apply VT markup");

        try {
            for (VTMatchSet matchSet : vtSession.getMatchSets()) {
                for (VTMatch match : matchSet.getMatches()) {
                    VTAssociation assoc = match.getAssociation();
                    if (assoc.getStatus() != VTAssociationStatus.ACCEPTED) continue;

                    Collection<VTMarkupItem> markupItems = assoc.getMarkupItems(ctx.getMonitor());
                    for (VTMarkupItem item : markupItems) {
                        try {
                            if (item.canApply()) {
                                item.apply(VTMarkupItemApplyActionType.REPLACE, new ToolOptions("VT"));
                                applied++;
                            }
                        } catch (Exception e) {
                            errors++;
                        }
                    }
                }
            }
            dest.endTransaction(txId, true);
        } catch (Exception e) {
            dest.endTransaction(txId, false);
            throw e;
        }

        JsonObject result = new JsonObject();
        result.addProperty("applied", applied);
        result.addProperty("errors", errors);
        return result;
    }

    /**
     * Get available correlator names.
     */
    public JsonObject getAvailableCorrelators() {
        JsonArray correlators = new JsonArray();

        // List known correlators
        String[] knownCorrelators = {
            "Exact Function Bytes Match",
            "Exact Function Instructions Match",
            "Exact Function Mnemonics Match",
            "Exact Symbol Name Match",
            "Combined Function and Data Reference Match",
            "Similar Symbol Name Match",
        };

        for (String name : knownCorrelators) {
            JsonObject entry = new JsonObject();
            entry.addProperty("name", name);
            VTAbstractProgramCorrelatorFactory factory = findFactory(name);
            entry.addProperty("available", factory != null);
            correlators.add(entry);
        }

        JsonObject result = new JsonObject();
        result.add("correlators", correlators);
        return result;
    }

    /**
     * Find a correlator factory by name.
     */
    private VTAbstractProgramCorrelatorFactory findFactory(String name) {
        try {
            // Use ClassSearcher to find correlator factories
            List<VTAbstractProgramCorrelatorFactory> factories =
                ghidra.util.classfinder.ClassSearcher.getInstances(VTAbstractProgramCorrelatorFactory.class);

            for (VTAbstractProgramCorrelatorFactory factory : factories) {
                if (factory.getName().equals(name) ||
                    factory.getName().contains(name)) {
                    return factory;
                }
            }
        } catch (Exception e) {
            ctx.getLog().warn("Error searching for correlator factory: " + e.getMessage());
        }
        return null;
    }
}

package com.ghidramcp.operations;

import com.ghidramcp.GhidraContext;
import com.ghidramcp.GhidraEngine;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import java.io.File;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Data type operations: create/update/delete structures, enums, unions, typedefs,
 * set data types at addresses, read data values, set function prototypes and
 * custom signatures.
 */
public class DataTypeOps {
    private final GhidraContext ctx;

    public DataTypeOps(GhidraContext ctx) {
        this.ctx = ctx;
    }

    // ==================== LIST / GET DATA TYPES ====================

    /**
     * List data types with optional filtering and pagination.
     */
    public GhidraEngine.ListDataTypesResult listDataTypes(int offset, int limit, String filter, String regex, String category) {
        List<GhidraEngine.DataTypeInfo> types = new ArrayList<>();
        DataTypeManager dtm = ctx.getProgram().getDataTypeManager();
        Object[] filterArgs = GhidraContext.prepareFilter(filter, regex);
        String filterLower = (String) filterArgs[0];
        Pattern compiled = (Pattern) filterArgs[1];

        // Single-pass: count total and collect page simultaneously
        int total = 0;
        int skipped = 0;
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();

            // Filter by category (proper path matching)
            if (category != null && !matchesCategory(dt.getCategoryPath().getPath(), category)) {
                continue;
            }

            if (!GhidraContext.passesFilter(dt.getName(), filterLower, compiled)) {
                continue;
            }

            total++;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (types.size() >= limit) continue;  // continue to count total

            GhidraEngine.DataTypeInfo info = new GhidraEngine.DataTypeInfo();
            info.name = dt.getName();
            info.category = dt.getCategoryPath().getPath();
            info.size = dt.getLength();
            info.description = dt.getDescription();

            if (dt instanceof Structure) {
                info.type = "structure";
            } else if (dt instanceof Union) {
                info.type = "union";
            } else if (dt instanceof ghidra.program.model.data.Enum) {
                info.type = "enum";
            } else if (dt instanceof TypeDef) {
                info.type = "typedef";
            } else if (dt instanceof Pointer) {
                info.type = "pointer";
            } else if (dt instanceof Array) {
                info.type = "array";
            } else if (dt instanceof FunctionDefinition) {
                info.type = "function";
            } else {
                info.type = "builtin";
            }

            types.add(info);
        }

        return new GhidraEngine.ListDataTypesResult(types, total);
    }

    /**
     * Category path matching: exact match or starts-with with "/" separator.
     * e.g. "/D2" matches "/D2" and "/D2/sub" but not "/D2Foo"
     */
    private boolean matchesCategory(String path, String category) {
        if (path.equals(category)) return true;
        return path.startsWith(category + "/");
    }

    /**
     * Get detailed data type info
     */
    public GhidraEngine.DataTypeDetail getDataType(String name, String category) throws Exception {
        DataTypeManager dtm = ctx.getProgram().getDataTypeManager();
        DataType dt = null;

        // Search for the data type
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equals(name)) {
                if (category == null || candidate.getCategoryPath().getPath().contains(category)) {
                    dt = candidate;
                    break;
                }
            }
        }

        if (dt == null) {
            throw new Exception("Data type not found: " + name);
        }

        GhidraEngine.DataTypeDetail detail = new GhidraEngine.DataTypeDetail();
        detail.name = dt.getName();
        detail.category = dt.getCategoryPath().getPath();
        detail.size = dt.getLength();
        detail.description = dt.getDescription();
        detail.alignment = dt.getAlignment();

        if (dt instanceof Union) {
            detail.type = "union";
            Union union = (Union) dt;
            detail.fields = new ArrayList<>();
            for (DataTypeComponent comp : union.getComponents()) {
                GhidraEngine.FieldDetail field = new GhidraEngine.FieldDetail();
                field.name = comp.getFieldName();
                field.dataType = comp.getDataType().getName();
                field.offset = comp.getOffset();
                field.size = comp.getLength();
                field.comment = comp.getComment();
                detail.fields.add(field);
            }
        } else if (dt instanceof Structure) {
            detail.type = "structure";
            Structure struct = (Structure) dt;
            detail.fields = new ArrayList<>();
            for (DataTypeComponent comp : struct.getComponents()) {
                GhidraEngine.FieldDetail field = new GhidraEngine.FieldDetail();
                field.name = comp.getFieldName();
                field.dataType = comp.getDataType().getName();
                field.offset = comp.getOffset();
                field.size = comp.getLength();
                field.comment = comp.getComment();
                detail.fields.add(field);
            }
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            detail.type = "enum";
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
            detail.values = new ArrayList<>();
            for (String enumName : enumType.getNames()) {
                GhidraEngine.DataTypeDetail.EnumValueDetail ev = new GhidraEngine.DataTypeDetail.EnumValueDetail();
                ev.name = enumName;
                ev.value = enumType.getValue(enumName);
                detail.values.add(ev);
            }
        } else if (dt instanceof TypeDef) {
            detail.type = "typedef";
            TypeDef td = (TypeDef) dt;
            detail.underlyingType = td.getBaseDataType().getName();
        } else if (dt instanceof ghidra.program.model.data.FunctionDefinition) {
            detail.type = "function";
            ghidra.program.model.data.FunctionDefinition funcDef = (ghidra.program.model.data.FunctionDefinition) dt;
            detail.returnType = funcDef.getReturnType().getDisplayName();
            detail.hasVarArgs = funcDef.hasVarArgs();
            String ccName = funcDef.getCallingConventionName();
            if (ccName != null && !ccName.isEmpty() && !ccName.equals("unknown")) {
                detail.callingConvention = ccName;
            }
            detail.parameters = new ArrayList<>();
            for (ghidra.program.model.data.ParameterDefinition param : funcDef.getArguments()) {
                GhidraEngine.FunctionParamDetail pd = new GhidraEngine.FunctionParamDetail();
                pd.name = param.getName();
                pd.dataType = param.getDataType().getDisplayName();
                pd.ordinal = param.getOrdinal();
                detail.parameters.add(pd);
            }
        }

        return detail;
    }

    // ==================== CREATE DATA TYPES ====================

    /**
     * Create a new structure data type.
     */
    public GhidraEngine.StructureResult createStructure(String name, String category, List<GhidraEngine.StructField> fields, boolean packed) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        int txId = program.startTransaction("Create structure");
        try {
            // Determine category path
            CategoryPath catPath = category != null && !category.isEmpty()
                ? new CategoryPath(category)
                : CategoryPath.ROOT;

            // Calculate structure size from field offsets
            int maxOffset = 0;
            int maxSize = 0;
            for (GhidraEngine.StructField field : fields) {
                if (field.offset >= 0) {
                    BitFieldSpec bits = parseBitField(field.dataType);
                    DataType fieldDt = bits != null ? bits.base : ctx.resolveDataType(field.dataType);
                    int endOffset = field.offset + fieldDt.getLength();
                    if (endOffset > maxOffset + maxSize) {
                        maxOffset = field.offset;
                        maxSize = fieldDt.getLength();
                    }
                }
            }
            int structSize = maxOffset + maxSize;
            if (structSize < 1) structSize = 1;

            // Create the structure
            StructureDataType struct = new StructureDataType(catPath, name, structSize, dtm);

            // Add fields
            java.util.Map<Integer, Integer> bitCursor = new java.util.HashMap<>();
            for (GhidraEngine.StructField field : fields) {
                BitFieldSpec bits = parseBitField(field.dataType);
                if (bits != null) {
                    placeBitField(struct, field, bits, bitCursor, true);
                    continue;
                }
                DataType fieldDt = ctx.resolveDataType(field.dataType);
                if (field.offset >= 0) {
                    struct.replaceAtOffset(field.offset, fieldDt, fieldDt.getLength(), field.name, field.comment);
                } else {
                    struct.add(fieldDt, field.name, field.comment);
                }
            }

            // Add to data type manager
            DataType added = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

            program.endTransaction(txId, true);

            GhidraEngine.StructureResult result = new GhidraEngine.StructureResult();
            result.name = added.getName();
            result.category = added.getCategoryPath().getPath();
            result.size = added.getLength();
            return result;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Update an existing structure.
     *
     * Operations:
     *   replaceAll  — nuclear rebuild: deleteAll + re-add (was "replace")
     *   updateFields — surgical: rename/retype/comment specific fields by name or offset
     *   insertField  — insert new field, struct grows (was "addField")
     *   deleteField  — delete field by name, struct shrinks (was "removeField")
     *
     * Deprecated aliases (still work, return warning):
     *   replace    → replaceAll
     *   addField   → insertField
     *   removeField → deleteField
     */
    public GhidraEngine.StructureResult updateStructure(String name, String category, String operation,
                                            List<GhidraEngine.StructField> fields, String fieldName,
                                            boolean force) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        // Find the existing structure
        DataType dt = null;
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equals(name) && candidate instanceof Structure) {
                if (category == null || candidate.getCategoryPath().getPath().contains(category)) {
                    dt = candidate;
                    break;
                }
            }
        }

        if (dt == null) {
            throw new Exception("Structure not found: " + name);
        }

        Structure struct = (Structure) dt;
        String warning = null;

        // Resolve deprecated aliases
        String resolvedOp = operation;
        switch (operation) {
            case "replace":
                resolvedOp = "replaceAll";
                warning = "DEPRECATED: 'replace' is renamed to 'replaceAll'. Please update your code.";
                break;
            case "addField":
                resolvedOp = "insertField";
                warning = "DEPRECATED: 'addField' is renamed to 'insertField'. Please update your code.";
                break;
            case "removeField":
                resolvedOp = "deleteField";
                warning = "DEPRECATED: 'removeField' is renamed to 'deleteField'. Please update your code.";
                break;
        }

        int txId = program.startTransaction("Update structure");
        try {
            switch (resolvedOp) {
                case "replaceAll": {
                    // Safety check: reject if new size < old size (unless force=true)
                    if (fields != null && !force) {
                        int oldSize = struct.getLength();
                        int newMaxEnd = 0;
                        for (GhidraEngine.StructField field : fields) {
                            if (field.offset >= 0) {
                                DataType fieldDt = ctx.resolveDataType(field.dataType);
                                int endOffset = field.offset + fieldDt.getLength();
                                if (endOffset > newMaxEnd) {
                                    newMaxEnd = endOffset;
                                }
                            }
                        }
                        if (newMaxEnd > 0 && newMaxEnd < oldSize) {
                            throw new Exception(
                                "replaceAll would shrink " + name + " from " + oldSize + " to " + newMaxEnd + " bytes. " +
                                "This usually means you forgot fields. Use 'updateFields' to change specific fields, " +
                                "or pass force=true to override this safety check."
                            );
                        }
                    }
                    // Clear and replace all fields
                    struct.deleteAll();
                    if (fields != null) {
                        java.util.Map<Integer, Integer> bitCursor = new java.util.HashMap<>();
                        for (GhidraEngine.StructField field : fields) {
                            BitFieldSpec bits = parseBitField(field.dataType);
                            if (bits != null) {
                                placeBitField(struct, field, bits, bitCursor, false);
                                continue;
                            }
                            DataType fieldDt = ctx.resolveDataType(field.dataType);
                            if (field.offset >= 0) {
                                struct.insertAtOffset(field.offset, fieldDt, fieldDt.getLength(), field.name, field.comment);
                            } else {
                                struct.add(fieldDt, field.name, field.comment);
                            }
                        }
                    }
                    break;
                }

                case "updateFields": {
                    // Surgical batch update: identify fields by fieldName or offset, apply partial updates
                    if (fields == null || fields.isEmpty()) {
                        throw new Exception("updateFields requires a non-empty fields array");
                    }
                    for (GhidraEngine.StructField update : fields) {
                        DataTypeComponent comp = null;

                        // Find the component by name or offset
                        if (update.fieldName != null) {
                            comp = findComponentByName(struct, update.fieldName);
                            if (comp == null) {
                                throw new Exception("Field not found by name: " + update.fieldName + " in " + name);
                            }
                        } else if (update.offset >= 0) {
                            comp = struct.getComponentAt(update.offset);
                            if (comp == null) {
                                throw new Exception("No field at offset " + update.offset + " in " + name);
                            }
                        } else {
                            throw new Exception("updateFields: each field must have 'fieldName' or 'offset' to identify the target");
                        }

                        int offset = comp.getOffset();

                        // Apply type change if newDataType is provided
                        if (update.newDataType != null) {
                            DataType newDt = ctx.resolveDataType(update.newDataType);
                            String fieldNameToUse = update.newName != null ? update.newName : comp.getFieldName();
                            String commentToUse = update.comment != null ? update.comment : comp.getComment();
                            struct.replaceAtOffset(offset, newDt, newDt.getLength(), fieldNameToUse, commentToUse);
                        } else {
                            // Metadata-only changes (rename and/or comment)
                            if (update.newName != null) {
                                comp.setFieldName(update.newName);
                            }
                            if (update.comment != null) {
                                comp.setComment(update.comment);
                            }
                        }
                    }
                    break;
                }

                case "insertField": {
                    // Add new fields
                    if (fields != null) {
                        java.util.Map<Integer, Integer> bitCursor = new java.util.HashMap<>();
                        for (GhidraEngine.StructField field : fields) {
                            BitFieldSpec bits = parseBitField(field.dataType);
                            if (bits != null) {
                                placeBitField(struct, field, bits, bitCursor, true);
                                continue;
                            }
                            DataType fieldDt = ctx.resolveDataType(field.dataType);
                            if (field.offset >= 0) {
                                struct.insertAtOffset(field.offset, fieldDt, fieldDt.getLength(), field.name, field.comment);
                            } else {
                                struct.add(fieldDt, field.name, field.comment);
                            }
                        }
                    }
                    break;
                }

                case "deleteField": {
                    // Remove a field by name
                    if (fieldName != null) {
                        DataTypeComponent[] components = struct.getComponents();
                        for (DataTypeComponent comp : components) {
                            if (fieldName.equals(comp.getFieldName())) {
                                struct.delete(comp.getOrdinal());
                                break;
                            }
                        }
                    }
                    break;
                }

                default:
                    throw new Exception("Unknown operation: " + operation + ". Valid: replaceAll, updateFields, insertField, deleteField");
            }

            program.endTransaction(txId, true);

            GhidraEngine.StructureResult result = new GhidraEngine.StructureResult();
            result.name = struct.getName();
            result.category = struct.getCategoryPath().getPath();
            result.size = struct.getLength();
            result.warning = warning;
            return result;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    // ==================== BITFIELDS ====================

    /**
     * A member written as "int:3" — a base type plus a width in bits.
     */
    private static final class BitFieldSpec {
        DataType base;
        int bitSize;
    }

    /**
     * Recognise C bitfield syntax in a field's dataType. Returns null for an ordinary type.
     * Only a trailing ":<digits>" counts, so namespaced type names ("Foo::Bar") are safe.
     */
    private BitFieldSpec parseBitField(String dataType) throws Exception {
        if (dataType == null) {
            return null;
        }
        int colon = dataType.lastIndexOf(':');
        if (colon <= 0 || colon == dataType.length() - 1 || dataType.charAt(colon - 1) == ':') {
            return null;
        }
        String widthPart = dataType.substring(colon + 1).trim();
        if (!widthPart.matches("\\d+")) {
            return null;
        }
        BitFieldSpec spec = new BitFieldSpec();
        spec.base = ctx.resolveDataType(dataType.substring(0, colon).trim());
        spec.bitSize = Integer.parseInt(widthPart);
        int capacity = spec.base.getLength() * 8;
        if (spec.bitSize < 1 || spec.bitSize > capacity) {
            throw new Exception("Bitfield width " + spec.bitSize + " does not fit in "
                + spec.base.getName() + " (" + capacity + " bits): " + dataType);
        }
        return spec;
    }

    /**
     * Place a bitfield member.
     *
     * At an explicit offset, consecutive bitfields sharing that offset stack from the least
     * significant bit up, which is how a C compiler lays them out — so "int:1" members
     * declared in order end up in one storage unit instead of scattered into separate bytes.
     * An explicit bitOffset overrides the running position. Without an offset the member is
     * appended, which is what a packed structure wants.
     */
    private void placeBitField(Structure struct, GhidraEngine.StructField field, BitFieldSpec spec,
                               java.util.Map<Integer, Integer> bitCursor, boolean replaceExisting)
            throws Exception {
        if (field.offset < 0) {
            struct.addBitField(spec.base, spec.bitSize, field.name, field.comment);
            return;
        }
        int capacity = spec.base.getLength() * 8;
        int bitOffset = field.bitOffset >= 0
            ? field.bitOffset
            : bitCursor.getOrDefault(field.offset, 0);
        if (bitOffset + spec.bitSize > capacity) {
            throw new Exception("Bitfields at offset " + field.offset + " overflow "
                + spec.base.getName() + ": " + (bitOffset + spec.bitSize) + " bits used of "
                + capacity + ". Start a new offset, or widen the base type.");
        }
        // insertBitFieldAt inserts rather than overwrites, so make room first by clearing the
        // undefined bytes occupying the storage unit — but only the first time this offset is
        // used, or each bitfield would wipe out the ones already placed beside it.
        if (replaceExisting && !bitCursor.containsKey(field.offset)) {
            clearRange(struct, field.offset, spec.base.getLength());
        }
        struct.insertBitFieldAt(field.offset, spec.base.getLength(), bitOffset, spec.base,
                                spec.bitSize, field.name, field.comment);
        bitCursor.put(field.offset, bitOffset + spec.bitSize);
    }

    /**
     * Clear the components covering [offset, offset+length) so a bitfield storage unit can be
     * inserted there without pushing the rest of the structure along.
     */
    private void clearRange(Structure struct, int offset, int length) {
        for (int i = offset + length - 1; i >= offset; i--) {
            DataTypeComponent comp = struct.getComponentContaining(i);
            if (comp != null && !comp.getDataType().equals(DataType.DEFAULT)) {
                struct.clearComponent(comp.getOrdinal());
            }
        }
    }

    /**
     * Rename a single field in a structure (used by rename_symbol type="field").
     */
    public void renameStructField(String structName, String fieldName, String newName, String category) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        // Find the structure
        DataType dt = null;
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equals(structName) && candidate instanceof Structure) {
                if (category == null || candidate.getCategoryPath().getPath().contains(category)) {
                    dt = candidate;
                    break;
                }
            }
        }

        if (dt == null) {
            throw new Exception("Structure not found: " + structName);
        }

        Structure struct = (Structure) dt;
        DataTypeComponent comp = findComponentByName(struct, fieldName);
        if (comp == null) {
            throw new Exception("Field '" + fieldName + "' not found in " + structName);
        }

        int txId = program.startTransaction("Rename struct field");
        try {
            comp.setFieldName(newName);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Find a structure component by field name.
     */
    private DataTypeComponent findComponentByName(Structure struct, String fieldName) {
        for (DataTypeComponent comp : struct.getComponents()) {
            if (fieldName.equals(comp.getFieldName())) {
                return comp;
            }
        }
        return null;
    }

    /**
     * Create an enumeration data type.
     */
    public GhidraEngine.DataTypeResult createEnum(String name, Map<String, Long> values, String category, int size) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        int txId = program.startTransaction("Create enum");
        try {
            CategoryPath catPath = category != null && !category.isEmpty()
                ? new CategoryPath(category)
                : CategoryPath.ROOT;

            ghidra.program.model.data.EnumDataType enumType = new ghidra.program.model.data.EnumDataType(catPath, name, size, dtm);

            for (Map.Entry<String, Long> entry : values.entrySet()) {
                enumType.add(entry.getKey(), entry.getValue());
            }

            DataType added = dtm.addDataType(enumType, DataTypeConflictHandler.REPLACE_HANDLER);

            program.endTransaction(txId, true);

            GhidraEngine.DataTypeResult result = new GhidraEngine.DataTypeResult();
            result.name = added.getName();
            result.category = added.getCategoryPath().getPath();
            result.size = added.getLength();
            return result;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Create a union data type
     */
    public GhidraEngine.DataTypeResult createUnion(String name, List<GhidraEngine.StructField> fields, String category) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        int txId = program.startTransaction("Create union");
        try {
            CategoryPath catPath = category != null && !category.isEmpty()
                ? new CategoryPath(category)
                : CategoryPath.ROOT;

            UnionDataType union = new UnionDataType(catPath, name, dtm);

            for (GhidraEngine.StructField field : fields) {
                DataType fieldDt = ctx.resolveDataType(field.dataType);
                union.add(fieldDt, field.name, field.comment);
            }

            DataType added = dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);

            program.endTransaction(txId, true);

            GhidraEngine.DataTypeResult result = new GhidraEngine.DataTypeResult();
            result.name = added.getName();
            result.category = added.getCategoryPath().getPath();
            result.size = added.getLength();
            return result;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Create a typedef
     */
    public GhidraEngine.DataTypeResult createTypedef(String name, String baseTypeName, String category) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        int txId = program.startTransaction("Create typedef");
        try {
            CategoryPath catPath = category != null && !category.isEmpty()
                ? new CategoryPath(category)
                : CategoryPath.ROOT;

            DataType baseType = ctx.resolveDataType(baseTypeName);
            TypedefDataType typedef = new TypedefDataType(catPath, name, baseType, dtm);

            DataType added = dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);

            program.endTransaction(txId, true);

            GhidraEngine.DataTypeResult result = new GhidraEngine.DataTypeResult();
            result.name = added.getName();
            result.category = added.getCategoryPath().getPath();
            result.size = added.getLength();
            return result;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Create a function-definition datatype (a funcdef), the type a callback
     * field or parameter should have. Without one those stay void* /
     * undefined1*, which loses the call signature at every indirect call site.
     */
    public GhidraEngine.DataTypeResult createFuncdef(String name, String returnType,
            List<GhidraEngine.FuncdefParam> parameters, String callingConvention,
            String category) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        int txId = program.startTransaction("Create funcdef");
        try {
            CategoryPath catPath = category != null && !category.isEmpty()
                ? new CategoryPath(category)
                : CategoryPath.ROOT;

            FunctionDefinitionDataType fd = new FunctionDefinitionDataType(catPath, name, dtm);
            fd.setReturnType(returnType != null && !returnType.isEmpty()
                ? ctx.resolveDataType(returnType)
                : VoidDataType.dataType);

            if (parameters != null && !parameters.isEmpty()) {
                ParameterDefinition[] defs = new ParameterDefinition[parameters.size()];
                for (int i = 0; i < parameters.size(); i++) {
                    GhidraEngine.FuncdefParam p = parameters.get(i);
                    String pname = (p.name != null && !p.name.isEmpty())
                        ? p.name : ("param_" + (i + 1));
                    defs[i] = new ParameterDefinitionImpl(
                        pname, ctx.resolveDataType(p.dataType), p.comment);
                }
                fd.setArguments(defs);
            }

            // Most D2 callbacks are __fastcall; a funcdef left at the default would
            // reintroduce the wrong-convention problem set_prototype used to cause.
            if (callingConvention != null && !callingConvention.isEmpty()) {
                fd.setCallingConvention(callingConvention);
            }

            DataType added = dtm.addDataType(fd, DataTypeConflictHandler.REPLACE_HANDLER);

            program.endTransaction(txId, true);

            GhidraEngine.DataTypeResult result = new GhidraEngine.DataTypeResult();
            result.name = added.getName();
            result.category = added.getCategoryPath().getPath();
            result.size = added.getLength();
            return result;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Delete a data type
     */
    public void deleteDataType(String name, String category) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        // Find the data type
        DataType dt = null;
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equals(name)) {
                if (category == null || candidate.getCategoryPath().getPath().contains(category)) {
                    dt = candidate;
                    break;
                }
            }
        }

        if (dt == null) {
            throw new Exception("Data type not found: " + name);
        }

        int txId = program.startTransaction("Delete data type");
        try {
            dtm.remove(dt, ctx.getMonitor());
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    // ==================== SET DATA TYPE AT ADDRESS ====================

    /**
     * Set the data type at an address.
     */
    public void setDataType(String addressStr, String dataTypeName, int length) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(addressStr);
        DataType dt = ctx.resolveDataType(dataTypeName);

        int txId = program.startTransaction("Set data type");
        try {
            int len = length > 0 ? length : dt.getLength();
            // Clear existing code/data at the range before applying new type
            program.getListing().clearCodeUnits(address, address.add(Math.max(len - 1, 0)), false);
            program.getListing().createData(address, dt, len);
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    // ==================== READ DATA VALUE ====================

    /**
     * Read the initialized data value at an address, returning a structured result
     * that handles arrays, structs, pointers, enums, strings, and scalars.
     */
    public GhidraEngine.DataValueResult readDataValue(String addressStr) {
        Program program = ctx.getProgram();
        Address addr = ctx.parseAddress(addressStr);
        if (addr == null) return null;

        Data data = program.getListing().getDefinedDataAt(addr);
        if (data == null) return null;

        return readDataValueRecursive(data, 0);
    }

    private GhidraEngine.DataValueResult readDataValueRecursive(Data data, int depth) {
        if (depth > 5) {
            // Prevent infinite recursion -- return hex fallback
            Object val = data.getValue();
            return GhidraEngine.DataValueResult.scalar(val != null ? val.toString() : "0");
        }

        DataType dt = data.getBaseDataType();

        // String types
        if (dt instanceof AbstractStringDataType) {
            Object val = data.getValue();
            return GhidraEngine.DataValueResult.string(val != null ? val.toString() : "");
        }

        // Pointer types -- resolve to symbol name if possible
        if (dt instanceof Pointer) {
            try {
                Object val = data.getValue();
                if (val instanceof Address) {
                    Address target = (Address) val;
                    Symbol sym = ctx.getProgram().getSymbolTable().getPrimarySymbol(target);
                    if (sym != null) {
                        return GhidraEngine.DataValueResult.pointer(sym.getName(true));
                    }
                    return GhidraEngine.DataValueResult.pointer(target.toString());
                }
                return GhidraEngine.DataValueResult.pointer(val != null ? val.toString() : "0x0");
            } catch (Exception e) {
                return GhidraEngine.DataValueResult.pointer("0x0");
            }
        }

        // Array types -- recurse into each element
        if (dt instanceof Array) {
            int numComponents = data.getNumComponents();
            List<GhidraEngine.DataValueResult> elements = new ArrayList<>();
            for (int i = 0; i < numComponents; i++) {
                Data comp = data.getComponent(i);
                if (comp != null) {
                    elements.add(readDataValueRecursive(comp, depth + 1));
                }
            }
            return GhidraEngine.DataValueResult.array(elements);
        }

        // Struct types -- recurse into each field
        if (dt instanceof Structure) {
            int numComponents = data.getNumComponents();
            List<GhidraEngine.DataValueField> fields = new ArrayList<>();
            for (int i = 0; i < numComponents; i++) {
                Data comp = data.getComponent(i);
                if (comp != null) {
                    String fieldName = comp.getFieldName();
                    if (fieldName == null || fieldName.isEmpty()) {
                        fieldName = "field_" + i;
                    }
                    fields.add(new GhidraEngine.DataValueField(fieldName, readDataValueRecursive(comp, depth + 1)));
                }
            }
            return GhidraEngine.DataValueResult.struct(fields);
        }

        // Enum types -- resolve numeric value to name
        if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enumDt = (ghidra.program.model.data.Enum) dt;
            try {
                // Read only the enum's actual size (1/2/4 bytes), not always 8
                int enumSize = enumDt.getLength();
                long val;
                if (enumSize <= 1) {
                    val = data.getByte(0) & 0xFFL;
                } else if (enumSize <= 2) {
                    val = data.getShort(0) & 0xFFFFL;
                } else if (enumSize <= 4) {
                    val = data.getInt(0) & 0xFFFFFFFFL;
                } else {
                    val = data.getLong(0);
                }
                String enumName = enumDt.getName(val);
                return GhidraEngine.DataValueResult.enumVal(enumName != null ? enumName : String.valueOf(val));
            } catch (Exception e) {
                Object val = data.getValue();
                return GhidraEngine.DataValueResult.enumVal(val != null ? val.toString() : "0");
            }
        }

        // Scalar fallback (int, byte, float, etc.)
        try {
            Object val = data.getValue();
            return GhidraEngine.DataValueResult.scalar(val != null ? val.toString() : "0");
        } catch (Exception e) {
            return GhidraEngine.DataValueResult.scalar("0");
        }
    }

    // ==================== FUNCTION PROTOTYPES ====================

    /**
     * Set a function's prototype/signature.
     */
    public java.util.List<String> setPrototype(String functionAddress, String prototype, String description, boolean force) throws Exception {
        return setPrototype(functionAddress, prototype, description, null, force);
    }

    /**
     * Set a function's prototype/signature, optionally along with its calling convention.
     *
     * The convention may be given as its own argument or written into the signature the way
     * a C declaration does ("ushort __stdcall Foo(uint a)") — Ghidra's signature parser
     * chokes on the keyword, treating it as part of the return type, so it is lifted out
     * here. The function's existing convention is never silently reset: without an explicit
     * request it is preserved.
     */
    public java.util.List<String> setPrototype(String functionAddress, String prototype, String description,
                                               String callingConvention, boolean force) throws Exception {
        Program program = ctx.getProgram();
        Function func = ctx.requireFunction(functionAddress, null);
        Address address = func.getEntryPoint();

        ctx.assertReadBeforeWrite(func.getEntryPoint().toString(), func.getName(), force);

        java.util.List<String> warnings = new java.util.ArrayList<>();
        boolean clearStorage = false;

        // Lift a convention keyword out of the signature text; an explicit argument wins.
        ConventionInSignature parsed = extractCallingConvention(prototype);
        prototype = parsed.prototype;
        String wantedConvention = callingConvention != null ? callingConvention : parsed.convention;

        // A plain prototype string carries NO storage info. Functions with custom /
        // auto-detected register storage (e.g. __usercall EAX-return, __fastcall ECX/EDX,
        // or any analyzer-detected register params) would have that storage discarded and
        // reset to the architecture default (__stdcall) — producing phantom
        // in_EAX/in_ECX/unaff_E** reads and broken decompilation. Refuse by default and
        // direct the caller to set_custom_signature; proceed only with force=true ("yep sure").
        if (func.hasCustomVariableStorage()) {
            if (!force) {
                throw new Exception("Refusing set_prototype on '" + func.getName() + "' (" + functionAddress
                    + "): function has custom/register parameter storage (calling convention "
                    + func.getCallingConventionName() + "). Applying a plain prototype string would reset it to "
                    + "the default convention and break the decompile (phantom in_EAX/in_ECX/unaff_). "
                    + "Use set_custom_signature with explicit per-parameter storage, or set_function_variable_type "
                    + "to change only a parameter's type/name. Pass force=true to apply anyway (clears custom storage).");
            }
            clearStorage = true;
        }

        int txId = program.startTransaction("Set prototype");
        try {
            if (clearStorage) {
                func.setCustomVariableStorage(false);
                warnings.add("Cleared custom variable storage on '" + func.getName()
                    + "' before applying the prototype (force=true) — storage re-derived from the convention.");
            }
            // Parse the prototype and apply it
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(
                    program.getDataTypeManager(),
                    null  // No service provider in headless mode
                );

            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(
                func.getSignature(),
                prototype
            );

            // Use ApplyFunctionSignatureCmd to safely replace the signature
            // (avoids infinite loop in FunctionDB.removeParameter/loadVariables).
            // preserveCallingConvention=true keeps the function's existing calling
            // convention (and therefore its parameter-storage scheme) — only the parsed
            // types/names are applied. This stops the old behavior of forcing __stdcall.
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    address, sig, SourceType.USER_DEFINED,
                    true,   // preserveCallingConvention
                    false   // applyEmptyComposites
                );
            cmd.applyTo(program);

            if (wantedConvention != null) {
                applyCallingConvention(program, func, wantedConvention, warnings);
            }

            ctx.updateFunctionPlateComment(func, description);
            program.endTransaction(txId, true);
            ctx.updateFunctionModCount(func.getEntryPoint().toString());
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
        warnings.add("Calling convention: " + func.getCallingConventionName());
        return warnings;
    }

    /** A prototype string with any calling-convention keyword taken out of it. */
    private static final class ConventionInSignature {
        String prototype;
        String convention;
    }

    /**
     * Conventions as they are written in a declaration. Ghidra names them with two leading
     * underscores; the bare and single-underscore spellings are accepted because that is how
     * they turn up in headers and in decompiler output.
     */
    private static final java.util.Map<String, String> CONVENTION_KEYWORDS = java.util.Map.ofEntries(
        java.util.Map.entry("__cdecl", "__cdecl"),
        java.util.Map.entry("_cdecl", "__cdecl"),
        java.util.Map.entry("cdecl", "__cdecl"),
        java.util.Map.entry("__stdcall", "__stdcall"),
        java.util.Map.entry("_stdcall", "__stdcall"),
        java.util.Map.entry("stdcall", "__stdcall"),
        java.util.Map.entry("__fastcall", "__fastcall"),
        java.util.Map.entry("_fastcall", "__fastcall"),
        java.util.Map.entry("fastcall", "__fastcall"),
        java.util.Map.entry("__thiscall", "__thiscall"),
        java.util.Map.entry("_thiscall", "__thiscall"),
        java.util.Map.entry("thiscall", "__thiscall"),
        java.util.Map.entry("__vectorcall", "__vectorcall"),
        java.util.Map.entry("__pascal", "__pascal"),
        java.util.Map.entry("pascal", "__pascal"),
        java.util.Map.entry("__regcall", "__regcall")
    );

    private ConventionInSignature extractCallingConvention(String prototype) {
        ConventionInSignature out = new ConventionInSignature();
        out.prototype = prototype;
        if (prototype == null) {
            return out;
        }
        int paren = prototype.indexOf('(');
        String head = paren >= 0 ? prototype.substring(0, paren) : prototype;
        String tail = paren >= 0 ? prototype.substring(paren) : "";

        java.util.List<String> kept = new java.util.ArrayList<>();
        for (String token : head.trim().split("\\s+")) {
            String mapped = CONVENTION_KEYWORDS.get(token);
            if (mapped != null && out.convention == null) {
                out.convention = mapped;
            } else if (mapped == null) {
                kept.add(token);
            }
        }
        if (out.convention != null) {
            out.prototype = String.join(" ", kept) + tail;
        }
        return out;
    }

    /**
     * Apply a calling convention, checking it against what this program's compiler spec
     * actually knows — an unknown name would otherwise fail deep inside Ghidra.
     */
    private void applyCallingConvention(Program program, Function func, String convention,
                                        java.util.List<String> warnings) throws Exception {
        String requested = convention.startsWith("__") ? convention
            : CONVENTION_KEYWORDS.getOrDefault(convention, convention);
        java.util.Collection<String> known = program.getFunctionManager().getCallingConventionNames();
        if (!known.contains(requested)) {
            throw new Exception("Unknown calling convention '" + convention + "' for this program. "
                + "Available: " + String.join(", ", known)
                + ". For register conventions Ghidra has no name for (IDA's __usercall), use "
                + "set_custom_signature with explicit per-parameter storage.");
        }
        String before = func.getCallingConventionName();
        if (requested.equals(before)) {
            return;
        }
        func.setCallingConvention(requested);
        warnings.add("Calling convention changed from " + before + " to " + requested + ".");
    }

    /**
     * Set function signature with custom parameter storage (for non-standard calling conventions)
     */
    public void setCustomSignature(String functionAddress, String returnType, List<GhidraEngine.CustomParameter> parameters, String description) throws Exception {
        setCustomSignature(functionAddress, returnType, parameters, description, false);
    }

    public void setCustomSignature(String functionAddress, String returnType, List<GhidraEngine.CustomParameter> parameters, String description, boolean force) throws Exception {
        Program program = ctx.getProgram();
        Address address = ctx.parseAddress(functionAddress);
        Function func = program.getFunctionManager().getFunctionAt(address);

        if (func == null) {
            throw new Exception("Function not found at: " + functionAddress);
        }

        ctx.assertReadBeforeWrite(func.getEntryPoint().toString(), func.getName(), force);

        int txId = program.startTransaction("Set custom signature");
        try {
            // Parse return type and create return variable
            DataType retType = ctx.resolveDataType(returnType);

            // Create return variable with default storage (based on calling convention)
            // For custom storage, we need to specify where the return value goes
            ghidra.program.model.lang.Register eaxReg = program.getRegister("EAX");
            ghidra.program.model.listing.VariableStorage retStorage;
            if (retType.equals(VoidDataType.dataType)) {
                retStorage = ghidra.program.model.listing.VariableStorage.VOID_STORAGE;
            } else {
                retStorage = new ghidra.program.model.listing.VariableStorage(program, eaxReg);
            }

            ghidra.program.model.listing.ReturnParameterImpl retVar =
                new ghidra.program.model.listing.ReturnParameterImpl(retType, retStorage, program);

            // Build parameter list with custom storage
            List<Variable> params = new ArrayList<>();

            for (GhidraEngine.CustomParameter cp : parameters) {
                DataType paramType = ctx.resolveDataType(cp.dataType);
                ghidra.program.model.listing.VariableStorage storage = parseStorage(cp.storage, paramType.getLength());

                ghidra.program.model.listing.ParameterImpl param =
                    new ghidra.program.model.listing.ParameterImpl(
                        cp.name,
                        paramType,
                        storage,
                        program
                    );
                params.add(param);
            }

            // Update function with custom storage
            // When using CUSTOM_STORAGE, pass null for calling convention to let Ghidra use "unknown"
            func.updateFunction(
                null,  // null = use "unknown" calling convention
                retVar,
                params,
                Function.FunctionUpdateType.CUSTOM_STORAGE,
                true,  // force
                SourceType.USER_DEFINED
            );

            ctx.updateFunctionPlateComment(func, description);
            program.endTransaction(txId, true);
            ctx.updateFunctionModCount(func.getEntryPoint().toString());
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
    }

    /**
     * Parse storage specification into VariableStorage
     * Supports: "EAX", "ECX", "EDX", "EBX", "ESI", "EDI", "stack:0x4", etc.
     */
    private ghidra.program.model.listing.VariableStorage parseStorage(String storageSpec, int size) throws Exception {
        Program program = ctx.getProgram();
        if (storageSpec.startsWith("stack:")) {
            // Stack storage: "stack:0x4" means stack offset 4
            int offset = Integer.decode(storageSpec.substring(6));
            return new ghidra.program.model.listing.VariableStorage(
                program,
                program.getAddressFactory().getStackSpace().getAddress(offset),
                size
            );
        } else {
            // Register storage
            ghidra.program.model.lang.Register reg = program.getRegister(storageSpec);
            if (reg == null) {
                throw new Exception("Unknown register: " + storageSpec);
            }
            return new ghidra.program.model.listing.VariableStorage(program, reg);
        }
    }

    // ==================== TYPE ARCHIVE OPERATIONS ====================

    /**
     * Export data types from the current program to a .gdt archive file.
     * Copies all types under the given categories (or all if null).
     */
    public Map<String, Object> exportTypeArchive(String archivePath, List<String> categories) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager srcDtm = program.getDataTypeManager();

        File archiveFile = new File(archivePath);
        if (archiveFile.exists()) {
            archiveFile.delete();
        }

        FileDataTypeManager archiveDtm = FileDataTypeManager.createFileArchive(archiveFile);
        int txId = archiveDtm.startTransaction("Export types");
        try {
            int exported = 0;
            Iterator<DataType> iter = srcDtm.getAllDataTypes();
            while (iter.hasNext()) {
                DataType dt = iter.next();

                // Skip builtins and pointer/array derivatives — they'll be auto-created
                if (dt instanceof BuiltInDataType) continue;
                if (dt instanceof Pointer) continue;
                if (dt instanceof Array) continue;
                if (dt instanceof FunctionDefinition) continue;

                // Filter by category if specified
                if (categories != null && !categories.isEmpty()) {
                    String catPath = dt.getCategoryPath().getPath();
                    boolean match = false;
                    for (String cat : categories) {
                        if (catPath.startsWith(cat)) {
                            match = true;
                            break;
                        }
                    }
                    if (!match) continue;
                }

                archiveDtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                exported++;
            }

            archiveDtm.endTransaction(txId, true);
            archiveDtm.save();
            archiveDtm.close();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("archivePath", archiveFile.getAbsolutePath());
            result.put("exported", exported);
            result.put("sizeBytes", archiveFile.length());
            return result;
        } catch (Exception e) {
            archiveDtm.endTransaction(txId, false);
            archiveDtm.close();
            throw e;
        }
    }

    /**
     * Import data types from a .gdt archive into the current program.
     * Replaces existing types with the same name/path.
     */
    public Map<String, Object> importTypeArchive(String archivePath, List<String> categories) throws Exception {
        Program program = ctx.getProgram();
        DataTypeManager dstDtm = program.getDataTypeManager();

        File archiveFile = new File(archivePath);
        if (!archiveFile.exists()) {
            throw new Exception("Archive file not found: " + archivePath);
        }

        FileDataTypeManager archiveDtm = FileDataTypeManager.openFileArchive(archiveFile, false);
        int txId = program.startTransaction("Import type archive");
        try {
            int imported = 0;
            Iterator<DataType> iter = archiveDtm.getAllDataTypes();
            while (iter.hasNext()) {
                DataType dt = iter.next();

                if (dt instanceof BuiltInDataType) continue;
                if (dt instanceof Pointer) continue;
                if (dt instanceof Array) continue;

                // Filter by category if specified
                if (categories != null && !categories.isEmpty()) {
                    String catPath = dt.getCategoryPath().getPath();
                    boolean match = false;
                    for (String cat : categories) {
                        if (catPath.startsWith(cat)) {
                            match = true;
                            break;
                        }
                    }
                    if (!match) continue;
                }

                dstDtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                imported++;
            }

            program.endTransaction(txId, true);
            archiveDtm.close();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("archivePath", archiveFile.getAbsolutePath());
            result.put("imported", imported);
            return result;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            archiveDtm.close();
            throw e;
        }
    }
}

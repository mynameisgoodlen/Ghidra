//Finds functions that use given strings; dumps RVA, thumb flag, first bytes, callers/callees, decompiled C.
//Args: <outDir> <targetsFile>
//@category MCRE

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class FindTargets extends GhidraScript {

    private static final int MAX_DECOMPILED = 100;
    private static final int MAX_DECOMP_LINES = 400;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args.length > 0 ? args[0] : "ghidra_out");
        outDir.mkdirs();

        List<String> needles = new ArrayList<>();
        if (args.length > 1 && new File(args[1]).exists()) {
            for (String line : Files.readAllLines(Paths.get(args[1]))) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) needles.add(line);
            }
        }
        if (needles.isEmpty()) {
            needles.add("_launchVisibilityRebuild");
            needles.add("scheduleChunkBuild");
            needles.add("scheduleChunkSort");
        }
        println("needles: " + needles);

        ReferenceManager rm = currentProgram.getReferenceManager();
        Address base = currentProgram.getImageBase();
        println("image base: " + base);

        Map<Address, Set<String>> hits = new TreeMap<>();
        Set<String> seenFileMap = new HashSet<>();

        PrintWriter fileMap = new PrintWriter(new FileWriter(new File(outDir, "file_map.tsv")));
        PrintWriter strRefs = new PrintWriter(new FileWriter(new File(outDir, "string_refs.tsv")));
        fileMap.println("source_file\tfunc_rva\tfunc_size");
        strRefs.println("needle\tfunc_rva\tfunc_name\tstring");

        long scanned = 0;
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            scanned++;
            Object v;
            try {
                v = d.getValue();
            } catch (Exception e) {
                continue;
            }
            if (!(v instanceof String)) continue;
            String s = (String) v;

            boolean isSrc = s.contains("src-client") && s.endsWith(".cpp");
            String matched = null;
            for (String n : needles) {
                if (s.contains(n)) { matched = n; break; }
            }
            if (!isSrc && matched == null) continue;

            ReferenceIterator ri = rm.getReferencesTo(d.getAddress());
            while (ri.hasNext()) {
                Reference r = ri.next();
                Function f = getFunctionContaining(r.getFromAddress());
                if (f == null) continue;
                long rva = f.getEntryPoint().subtract(base);
                if (isSrc && seenFileMap.add(s + "|" + rva)) {
                    fileMap.printf("%s\t0x%08x\t%d%n", s, rva, f.getBody().getNumAddresses());
                }
                if (matched != null) {
                    hits.computeIfAbsent(f.getEntryPoint(), k -> new LinkedHashSet<>()).add(s);
                    strRefs.printf("%s\t0x%08x\t%s\t%s%n", matched, rva, f.getName(), s);
                }
            }
        }
        fileMap.close();
        strRefs.close();
        println("scanned " + scanned + " defined data items, " + hits.size() + " target functions");

        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(currentProgram);

        Register tmode = currentProgram.getRegister("TMode");
        PrintWriter tsv = new PrintWriter(new FileWriter(new File(outDir, "targets.tsv")));
        tsv.println("func_rva\tthumb\thook_addr\tsize\tname\tmatched_strings");

        int count = 0;
        for (Map.Entry<Address, Set<String>> e : hits.entrySet()) {
            if (monitor.isCancelled()) break;
            Function f = getFunctionAt(e.getKey());
            if (f == null) continue;

            long rva = f.getEntryPoint().subtract(base);
            boolean thumb = false;
            if (tmode != null) {
                RegisterValue rv = currentProgram.getProgramContext().getRegisterValue(tmode, f.getEntryPoint());
                if (rv != null && rv.hasValue()) thumb = rv.getUnsignedValue().intValue() == 1;
            }
            long hook = rva | (thumb ? 1 : 0);
            long size = f.getBody().getNumAddresses();

            String joined = String.join(" || ", e.getValue());
            if (joined.length() > 300) joined = joined.substring(0, 300) + "...";
            tsv.printf("0x%08x\t%b\t0x%08x\t%d\t%s\t%s%n", rva, thumb, hook, size, f.getName(), joined);

            if (count++ >= MAX_DECOMPILED) continue;

            PrintWriter w = new PrintWriter(new FileWriter(new File(outDir, String.format("fn_%08x.txt", rva))));
            w.printf("name: %s%n", f.getName());
            w.printf("rva: 0x%08x   thumb: %b   hook_addr(rva|thumb): 0x%08x   size: %d bytes%n", rva, thumb, hook, size);
            w.println("matched strings:");
            for (String s : e.getValue()) w.println("  " + s);

            try {
                Set<Function> callers = f.getCallingFunctions(monitor);
                w.printf("callers (%d):%n", callers.size());
                int n = 0;
                for (Function c : callers) {
                    if (n++ >= 15) break;
                    w.printf("  0x%08x %s%n", c.getEntryPoint().subtract(base), c.getName());
                }
                Set<Function> callees = f.getCalledFunctions(monitor);
                w.printf("callees (%d):%n", callees.size());
                n = 0;
                for (Function c : callees) {
                    if (n++ >= 30) break;
                    w.printf("  0x%08x %s%n", c.getEntryPoint().subtract(base), c.getName());
                }
            } catch (Exception ex) {
                w.println("callers/callees failed: " + ex.getMessage());
            }

            try {
                byte[] b = new byte[64];
                int got = currentProgram.getMemory().getBytes(f.getEntryPoint(), b);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < got; i++) sb.append(String.format("%02X ", b[i]));
                w.println("first bytes: " + sb.toString().trim());
            } catch (Exception ex) {
                w.println("bytes failed: " + ex.getMessage());
            }

            w.println();
            w.println("---- decompiled ----");
            try {
                DecompileResults res = di.decompileFunction(f, 90, monitor);
                if (res != null && res.decompileCompleted()) {
                    String[] lines = res.getDecompiledFunction().getC().split("\n");
                    for (int i = 0; i < lines.length && i < MAX_DECOMP_LINES; i++) w.println(lines[i]);
                    if (lines.length > MAX_DECOMP_LINES) w.println("... (" + (lines.length - MAX_DECOMP_LINES) + " more lines)");
                } else {
                    w.println("decompile failed: " + (res == null ? "null" : res.getErrorMessage()));
                }
            } catch (Exception ex) {
                w.println("decompile exception: " + ex.getMessage());
            }
            w.close();
        }
        tsv.close();
        di.dispose();
        println("done");
    }
}

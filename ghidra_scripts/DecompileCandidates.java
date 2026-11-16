//Decompiles function-start candidates produced by xref_scan.py (no whole-program analysis).
//A result is CONFIRMED only if the decompiled code really contains the string's (or cell's) address.
//Args: <outDir> <candidates.tsv>
//@category MCRE

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.ProgramContext;

public class DecompileCandidates extends GhidraScript {

    private static final int MAX_C_LINES = 700;
    private static final int MAX_INSNS = 120;
    private static final long TIME_BUDGET_MS = 50L * 60L * 1000L;
    private static final int CLEAR_BEFORE = 0x40;
    private static final int CLEAR_AFTER = 0x5000;

    private void clearAround(Address start) throws Exception {
        // wipes any earlier (possibly misaligned) disassembly, functions and Thumb/ARM context here
        clearListing(start.subtract(CLEAR_BEFORE), start.add(CLEAR_AFTER));
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args[0]);
        outDir.mkdirs();

        List<String[]> rows = new ArrayList<>();
        boolean first = true;
        for (String line : Files.readAllLines(Paths.get(args[1]))) {
            if (first) { first = false; continue; }          // header
            if (line.trim().isEmpty()) continue;
            rows.add(line.split("\t"));                      // name mode site start string
        }
        println("candidates: " + rows.size());

        Address base = currentProgram.getImageBase();
        long baseOff = base.getOffset();
        ProgramContext ctx = currentProgram.getProgramContext();
        Register tmode = currentProgram.getRegister("TMode");

        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(currentProgram);

        PrintWriter index = new PrintWriter(new FileWriter(new File(outDir, "decompiled_index.tsv")));
        index.println("name\tmode\tsite\tstart\tcontains_site\tconfirmed\tsize\tfile");

        Set<String> confirmedSites = new HashSet<>();
        Map<Long, String> textByStart = new HashMap<>();
        Map<Long, String> fileByStart = new HashMap<>();
        long t0 = System.currentTimeMillis();
        int written = 0;

        for (String[] r : rows) {
            if (monitor.isCancelled()) break;
            if (System.currentTimeMillis() - t0 > TIME_BUDGET_MS) { println("time budget reached"); break; }
            if (r.length < 5) continue;
            String name = r[0], mode = r[1];
            long siteV = Long.parseLong(r[2].replace("0x", ""), 16);
            long startV = Long.parseLong(r[3].replace("0x", ""), 16);
            long strV = Long.parseLong(r[4].replace("0x", ""), 16);

            String siteKey = name + "|" + siteV;
            if (confirmedSites.contains(siteKey)) continue;

            String probe = String.format("%08x", strV + baseOff);

            // function already decompiled for another target: just test this string against its text
            if (textByStart.containsKey(startV)) {
                boolean conf = textByStart.get(startV).contains(probe);
                index.printf("%s\t%s\t0x%08x\t0x%08x\ttrue\t%b\t-\t%s%n", name, mode, siteV, startV, conf,
                             fileByStart.get(startV));
                if (conf) confirmedSites.add(siteKey);
                continue;
            }

            Address startA = base.add(startV);
            Address siteA = base.add(siteV);
            try {
                clearAround(startA);
                if (tmode != null) {
                    ctx.setValue(tmode, startA, startA, BigInteger.valueOf(mode.equals("T") ? 1 : 0));
                }
                disassemble(startA);
                Function f = getFunctionAt(startA);
                if (f == null) f = createFunction(startA, null);
                if (f == null) {
                    index.printf("%s\t%s\t0x%08x\t0x%08x\tno_function\tfalse\t0\t-%n", name, mode, siteV, startV);
                    continue;
                }
                boolean contains = f.getBody().contains(siteA);
                long size = f.getBody().getNumAddresses();
                if (!contains) {
                    index.printf("%s\t%s\t0x%08x\t0x%08x\tfalse\tfalse\t%d\t-%n", name, mode, siteV, startV, size);
                    continue;
                }

                String full = "";
                String errMsg = null;
                try {
                    DecompileResults res = di.decompileFunction(f, 60, monitor);
                    if (res != null && res.decompileCompleted()) {
                        full = res.getDecompiledFunction().getC();
                    } else {
                        errMsg = (res == null ? "null" : res.getErrorMessage());
                    }
                } catch (Exception ex) {
                    errMsg = "decompile exception: " + ex.getMessage();
                }
                String lower = full.toLowerCase();
                boolean confirmed = lower.contains(probe);

                String safe = name.replaceAll("[^A-Za-z0-9_]+", "_");
                String fname = String.format("dec_%s_%08x%s.txt", safe, startV, confirmed ? "" : "_unconfirmed");
                textByStart.put(startV, lower);
                fileByStart.put(startV, fname);
                index.printf("%s\t%s\t0x%08x\t0x%08x\ttrue\t%b\t%d\t%s%n", name, mode, siteV, startV, confirmed, size, fname);
                if (confirmed) confirmedSites.add(siteKey);

                PrintWriter w = new PrintWriter(new FileWriter(new File(outDir, fname)));
                w.printf("target: %s%n", name);
                w.printf("confirmed (decompile contains string address 0x%s): %b%n", probe, confirmed);
                w.printf("mode: %s (T = Thumb: hook address must have bit0 set)   start: 0x%08x   hook_addr: 0x%08x   size: %d%n",
                         mode, startV, mode.equals("T") ? (startV | 1) : startV, size);
                w.printf("string reference at: 0x%08x   string: %s%n", siteV, r[4]);
                try {
                    byte[] b = new byte[64];
                    int got = currentProgram.getMemory().getBytes(startA, b);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < got; i++) sb.append(String.format("%02X ", b[i]));
                    w.println("first bytes: " + sb.toString().trim());
                } catch (Exception ex) {
                    w.println("bytes failed: " + ex.getMessage());
                }
                w.println();
                w.println("---- first instructions (addresses shown as file offsets) ----");
                InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
                int n = 0;
                while (it.hasNext() && n++ < MAX_INSNS) {
                    Instruction ins = it.next();
                    w.printf("%08x: %s%n", ins.getAddress().subtract(base), ins.toString());
                }
                w.println();
                w.println("---- decompiled (Ghidra addresses = file offset + 0x" + Long.toHexString(baseOff) + ") ----");
                if (errMsg != null) {
                    w.println("decompile failed: " + errMsg);
                } else {
                    String[] lines = full.split("\n");
                    for (int i = 0; i < lines.length && i < MAX_C_LINES; i++) w.println(lines[i]);
                    if (lines.length > MAX_C_LINES) w.println("... (" + (lines.length - MAX_C_LINES) + " more lines)");
                }
                w.close();
                written++;
                println((confirmed ? "CONFIRMED: " : "unconfirmed: ") + name + " @ 0x" + Long.toHexString(startV));
            } catch (Exception ex) {
                index.printf("%s\t%s\t0x%08x\t0x%08x\terror\tfalse\t0\t%s%n", name, mode, siteV, startV,
                             String.valueOf(ex.getMessage()).replace('\t', ' ').replace('\n', ' '));
            }
        }
        index.close();
        di.dispose();
        println("done, files written: " + written);
    }
}

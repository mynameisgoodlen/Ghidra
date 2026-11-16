//Decompiles the function-start candidates found by xref_scan.py. No whole-program analysis needed.
//Args: <outDir> <candidates.tsv>
//@category MCRE

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
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
    private static final int MAX_INSNS = 150;
    private static final long TIME_BUDGET_MS = 45L * 60L * 1000L;

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
        ProgramContext ctx = currentProgram.getProgramContext();
        Register tmode = currentProgram.getRegister("TMode");

        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(currentProgram);

        PrintWriter index = new PrintWriter(new FileWriter(new File(outDir, "decompiled_index.tsv")));
        index.println("name\tmode\tsite\tstart\tcontains_site\tsize\tfile");

        Set<String> satisfiedSites = new HashSet<>();
        Set<String> doneStarts = new HashSet<>();
        long t0 = System.currentTimeMillis();

        for (String[] r : rows) {
            if (monitor.isCancelled()) break;
            if (System.currentTimeMillis() - t0 > TIME_BUDGET_MS) { println("time budget reached"); break; }
            if (r.length < 5) continue;
            String name = r[0], mode = r[1];
            long siteV = Long.parseLong(r[2].replace("0x", ""), 16);
            long startV = Long.parseLong(r[3].replace("0x", ""), 16);

            String siteKey = name + "|" + siteV;
            if (satisfiedSites.contains(siteKey)) continue;
            String startKey = mode + "|" + startV;
            if (!doneStarts.add(startKey + "|" + siteV)) continue;

            Address startA = base.add(startV);
            Address siteA = base.add(siteV);
            try {
                if (tmode != null) {
                    ctx.setValue(tmode, startA, startA, BigInteger.valueOf(mode.equals("T") ? 1 : 0));
                }
                disassemble(startA);
                Function f = getFunctionAt(startA);
                if (f == null) f = createFunction(startA, null);
                if (f == null) {
                    index.printf("%s\t%s\t0x%08x\t0x%08x\tno_function\t0\t-%n", name, mode, siteV, startV);
                    continue;
                }
                boolean contains = f.getBody().contains(siteA);
                long size = f.getBody().getNumAddresses();
                String safe = name.replaceAll("[^A-Za-z0-9_]+", "_");
                String fname = String.format("dec_%s_%08x.txt", safe, startV);
                index.printf("%s\t%s\t0x%08x\t0x%08x\t%b\t%d\t%s%n", name, mode, siteV, startV, contains, size, fname);
                if (!contains) continue;
                satisfiedSites.add(siteKey);

                PrintWriter w = new PrintWriter(new FileWriter(new File(outDir, fname)));
                w.printf("target: %s%n", name);
                w.printf("mode: %s (T = Thumb, hook address must have bit0 set)   start: 0x%08x   hook_addr: 0x%08x   size: %d%n",
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
                w.println("---- first instructions ----");
                InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
                int n = 0;
                while (it.hasNext() && n++ < MAX_INSNS) {
                    Instruction ins = it.next();
                    w.printf("%08x: %s%n", ins.getAddress().subtract(base), ins.toString());
                }
                w.println();
                w.println("---- decompiled ----");
                try {
                    DecompileResults res = di.decompileFunction(f, 60, monitor);
                    if (res != null && res.decompileCompleted()) {
                        String[] lines = res.getDecompiledFunction().getC().split("\n");
                        for (int i = 0; i < lines.length && i < MAX_C_LINES; i++) w.println(lines[i]);
                        if (lines.length > MAX_C_LINES) w.println("... (" + (lines.length - MAX_C_LINES) + " more lines)");
                    } else {
                        w.println("decompile failed: " + (res == null ? "null" : res.getErrorMessage()));
                    }
                } catch (Exception ex) {
                    w.println("decompile exception: " + ex.getMessage());
                }
                w.close();
                println("ok: " + name + " @ 0x" + Long.toHexString(startV));
            } catch (Exception ex) {
                index.printf("%s\t%s\t0x%08x\t0x%08x\terror:%s\t0\t-%n", name, mode, siteV, startV,
                             String.valueOf(ex.getMessage()).replace('\t', ' '));
            }
        }
        index.close();
        di.dispose();
        println("done");
    }
}

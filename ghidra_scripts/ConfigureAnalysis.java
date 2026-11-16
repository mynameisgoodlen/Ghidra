//Turns off the slowest analyzers so a huge library finishes on a small CI runner.
//@category MCRE

import ghidra.app.script.GhidraScript;

public class ConfigureAnalysis extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] off = {
            "Decompiler Parameter ID",
            "Decompiler Switch Analysis",
            "Aggressive Instruction Finder",
            "Demangler GNU",
            "Embedded Media",
            "Create Address Tables"
        };
        for (String name : off) {
            try {
                setAnalysisOption(currentProgram, name, "false");
                println("analyzer off: " + name);
            } catch (Exception e) {
                println("could not change analyzer '" + name + "': " + e.getMessage());
            }
        }
    }
}

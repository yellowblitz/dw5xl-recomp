// Import candidate review CSVs as Ghidra ANALYSIS BOOKMARKS ONLY.
// Supports tools/jp/survey_prologues.py, survey_runtime_entries.py and
// corroborate_candidates.py CSV output. Never creates functions, names,
// disassembly, ranges or relocations from unverified candidate addresses.
//@category DW5XL

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public class BookmarkJPReviewCandidates extends GhidraScript {
    private static final int MAX_ROWS = 100000;
    private static final int MAX_FILE_BYTES = 8 * 1024 * 1024;
    private static final Pattern HEX32 = Pattern.compile("0[xX][0-9a-fA-F]{8}");

    private static class Entry {
        Address address;
        String comment;
        Entry(Address address, String comment) {
            this.address = address;
            this.comment = comment;
        }
    }

    // Valid for the simple UTF-8 CSV schemas emitted by the JP analysis tools.
    private static List<String> fields(String line) throws Exception {
        ArrayList<String> values = new ArrayList<>();
        StringBuilder value = new StringBuilder();
        boolean quoted = false;
        boolean afterQuote = false;
        for (int i = 0; i < line.length(); ++i) {
            char c = line.charAt(i);
            if (quoted) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        value.append('"');
                        ++i;
                    } else {
                        quoted = false;
                        afterQuote = true;
                    }
                } else {
                    value.append(c);
                }
            } else if (c == ',') {
                values.add(value.toString());
                value.setLength(0);
                afterQuote = false;
            } else if (c == '"' && value.length() == 0 && !afterQuote) {
                quoted = true;
            } else if (afterQuote && (c == ' ' || c == '\t')) {
                // Allow trailing whitespace between a quote and delimiter.
            } else if (afterQuote || c == '"') {
                throw new Exception("Malformed candidate CSV field");
            } else {
                value.append(c);
            }
        }
        if (quoted) {
            throw new Exception("Unclosed quoted CSV field");
        }
        values.add(value.toString());
        return values;
    }

    private static String moduleName(String source) {
        String normalized = source.toLowerCase(Locale.ROOT).trim()
                                  .replace("_", "").replace("-", "");
        if (normalized.startsWith("ovl") && normalized.endsWith(".bin")) {
            normalized = normalized.substring(0, normalized.length() - 4);
        }
        return normalized;
    }

    private static String get(Map<String, Integer> columns, List<String> row, String name) {
        Integer at = columns.get(name);
        return (at == null || at < 0 || at >= row.size()) ? "" : row.get(at).trim();
    }

    @Override
    protected void run() throws Exception {
        File csv = askFile("Japanese candidate CSV (bookmarks only)", "Import");
        if (!csv.isFile() || csv.length() > MAX_FILE_BYTES) {
            throw new Exception("Missing file or candidate CSV exceeds 8 MiB");
        }

        String module = moduleName(askString("JP module", "main, ovl00, ovl01, ovl02"));
        if (!(module.equals("main") || module.equals("ovl00") ||
              module.equals("ovl01") || module.equals("ovl02"))) {
            throw new Exception("Expected main, ovl00, ovl01, or ovl02");
        }
        String programName = currentProgram.getName().toLowerCase(Locale.ROOT);
        String expectedFragment = module.equals("main") ? "slpm_661.01" :
                                  "ovl_" + module.substring(3);
        if (!programName.contains(expectedFragment)) {
            throw new Exception("Program name does not match selected JP module: " +
                                currentProgram.getName() + " vs " + module +
                                ". Rename the imported program to its original game filename.");
        }

        int accepted = 0, unrelated = 0, unmapped = 0;
        List<Entry> entries = new ArrayList<>();
        String category;
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                 new FileInputStream(csv), StandardCharsets.UTF_8))) {
            String header = in.readLine();
            if (header == null) {
                throw new Exception("Empty candidate CSV");
            }
            header = header.replace("\uFEFF", "");
            List<String> headerFields = fields(header);
            Map<String, Integer> columns = new HashMap<>();
            for (int j = 0; j < headerFields.size(); ++j) {
                if (columns.put(headerFields.get(j).trim(), j) != null) {
                    throw new Exception("Duplicate CSV column name");
                }
            }
            if (!columns.containsKey("module") ||
                !(columns.containsKey("guest_address") || columns.containsKey("address"))) {
                throw new Exception("Expected module and guest_address/address columns");
            }
            boolean ranked = columns.containsKey("direct_jal_word_hits");
            category = ranked ? "JP candidate: static JAL correlation" :
                       columns.containsKey("kind") ? "JP candidate: header/bookmark" :
                       "JP candidate: stack prologue";
            String line;
            int lineNumber = 1;
            while ((line = in.readLine()) != null) {
                ++lineNumber;
                if (monitor.isCancelled()) {
                    throw new Exception("Cancelled before placing any bookmarks");
                }
                if (line.isEmpty()) {
                    continue;
                }
                if (lineNumber > MAX_ROWS + 1) {
                    throw new Exception("Too many candidate rows");
                }
                List<String> row = fields(line);
                if (row.size() != headerFields.size()) {
                    throw new Exception("CSV field count mismatch at line " + lineNumber);
                }
                if (!moduleName(get(columns, row, "module")).equals(module)) {
                    ++unrelated;
                    continue;
                }
                String literal = get(columns, row,
                                     columns.containsKey("guest_address") ?
                                     "guest_address" : "address");
                if (!HEX32.matcher(literal).matches()) {
                    throw new Exception("Invalid 32-bit guest address at line " + lineNumber);
                }
                long number = Long.parseUnsignedLong(literal.substring(2), 16);
                if ((number & 3) != 0) {
                    throw new Exception("Unaligned candidate at line " + lineNumber);
                }
                String status = get(columns, row,
                                    columns.containsKey("review_status") ?
                                    "review_status" : "status");
                if (!status.isEmpty() && !status.equals("CANDIDATE_NOT_VERIFIED")) {
                    throw new Exception("Unexpected candidate status at line " + lineNumber);
                }
                Address address = toAddr(literal);
                if (address == null || currentProgram.getMemory().getBlock(address) == null) {
                    ++unmapped;
                    continue;
                }
                String evidence = get(columns, row, "evidence");
                String hits = get(columns, row, "direct_jal_word_hits");
                String kind = get(columns, row, "kind");
                String comment = "UNVERIFIED JP REVIEW CANDIDATE; " +
                                 (kind.isEmpty() ? "" : "kind=" + kind + "; ") +
                                 "evidence=" + evidence +
                                 (hits.isEmpty() ? "" : "; syntactic JAL words=" + hits) +
                                 ". Do not automatically create a function.";
                entries.add(new Entry(address, comment));
                ++accepted;
            }
        }
        if (accepted == 0) {
            throw new Exception("No mapped candidate addresses for module " + module +
                                "; no bookmarks changed");
        }
        // Only analysis bookmarks are created. Listing, functions, names,
        // addresses and bytes remain unchanged by this script.
        for (Entry entry : entries) {
            if (monitor.isCancelled()) {
                break;
            }
            currentProgram.getBookmarkManager().setBookmark(
                    entry.address, BookmarkType.ANALYSIS, category, entry.comment);
        }
        println("JP review bookmarks: considered " + accepted + " mapped candidates, " +
                unrelated + " from other modules, " + unmapped + " unmapped. " +
                "No functions or disassembly created.");
    }
}

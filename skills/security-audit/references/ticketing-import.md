# Importing findings into a ticketing system

Give the user only the section for their system, with the real file path.
Each ticket's description starts with its **Finding ID** (e.g. AEK-3f9a1c02b7).
The same problem keeps the same ID on every audit, so tell the user how to
avoid duplicates on re-runs (last bullet of each section).

`security-findings.csv` is always created. It opens in any spreadsheet app
and works as an audit evidence log on its own.

## Jira
File: `security-findings-jira.csv` (split into `-part2`, ... above 1,500 rows)

1. In Jira, open the project, then **⋯ → Import work items / Import issues
   from CSV** (wording varies; a Jira admin may be needed).
2. Upload the file. In **Advanced**, keep encoding **UTF-8** and delimiter
   **comma**.
3. Map the columns: Summary → Summary, Issue Type → Issue type / Work type,
   Priority → Priority, Description → Description, all Labels → Labels.
4. On the value-mapping screen, map Priority values (High / Medium / Low) and
   Issue Type "Bug" to what your project uses.
- **Re-runs:** Jira's importer doesn't detect duplicates. Before importing,
  search Jira for each Finding ID, or import only the new rows.

## Linear
File: `security-findings-linear.csv` (Linear's own CSV format)

1. Linear imports CSV through its CLI importer (workspace admin required):
   **Settings → Administration → Import/Export → CLI import → Open**, then
   follow the instructions to run it.
2. Choose the **"Linear" CSV** option, select the file and the target team.
3. Priorities in the file are High / Medium / Low. If your Linear version
   expects different values, adjust them in the file first.
- **Re-runs:** Linear skips issues already imported into the same team.

## Asana
File: `security-findings-asana.csv`

1. In Asana: **+ Create → Project → Import spreadsheet** (or, in an existing
   project, **⋯ → Import → CSV**).
2. Upload the file. Columns are read in order: **Name**, **Description**,
   **Section** (High / Medium / Low, so each severity becomes a section),
   **Assignee** (empty; assign later).
3. "Finding ID" and "Severity" become custom fields on Premium plans; on other
   plans they're added to the task description.
- **Re-runs:** Asana doesn't detect duplicates. Filter by the Finding ID
  custom field, or import only new rows.

## monday.com
File: `security-findings-monday.csv`

1. On a board: **⋯ (board menu) → Import items** and upload the CSV, or
   create a new board from **+ Add → Import data**.
2. Choose **Name** as the item name column.
3. Map the other columns: Severity and Status → Status columns, Finding ID and
   Location → Text, Description and Fix → Long text.
- **Re-runs:** when importing into the same board, choose **Finding ID** as
  the matching column. Rows whose ID already exists on the board are skipped.

<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Get folder name
$folderName = basename(__DIR__);
$folderNameLower = strtolower($folderName);

// Get XLSX files
$files = glob("*.xlsx");
$data = [];
$baseNames = [];

// Match dated or undated files
$pattern = '/^(.*)-\d{2}-\d{2}-\d{2}\.xlsx$/';

foreach ($files as $file) {
    if (preg_match($pattern, $file, $matches)) {
        $base = $matches[1];
    } else {
        $base = preg_replace('/\.xlsx$/i', '', $file);
    }

    $mtime = filemtime($file);
    $dateKey = date("Y-m-d", $mtime);

    if (!isset($data[$dateKey])) {
        $data[$dateKey] = [];
    }

    $data[$dateKey][$base] = [
        'filename' => $file,
        'mtime' => $mtime
    ];

    $baseNames[$base] = true;
}

// Sort base names alphabetically
$baseNames = array_keys($baseNames);
sort($baseNames);

// Sort dates newest first initially
uksort($data, function($a, $b) {
    return strcmp($b, $a);
});

// Helper: map base filename to expected log path
function logSuffixForBase($baseName) {
    $parts = explode('_', $baseName, 2);
    if (count($parts) < 2) return null; // no suffix
    return $parts[1];
}
function logPathForBase($baseName, $folderLower) {
    $suffix = logSuffixForBase($baseName);
    if ($suffix === null) return null;
    return "logs/{$folderLower}_{$suffix}.log";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title><?php echo htmlspecialchars($folderName); ?> Excel Reports</title>
<style>
    body { font-family: Arial, sans-serif; margin:0; background: #fafafa; }
    h1 { margin: 20px; }
    .table-container { max-height: 90vh; overflow-y: auto; margin: 20px; border: 1px solid #ccc; background: #fff; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: center; cursor: default; }
    th { background: #f0f0f0; position: sticky; top: 0; z-index: 2; }
    td.missing { background-color: #000; }
    td a { color: #0066cc; text-decoration: none; }
    td a:hover { text-decoration: underline; }
    th.sort-asc::after { content: "▲"; margin-left: 5px; }
    th.sort-desc::after { content: "▼"; margin-left: 5px; }
</style>
</head>
<body>
<h1>Available Excel Reports from <?php echo htmlspecialchars($folderName); ?> Panorama</h1>
<div class="table-container">
    <table id="reportTable">
        <thead>
            <tr>
                <th>Date (Modified)</th>
                <th>Days Ago</th> <!-- Uns sortable -->
                <?php foreach ($baseNames as $base): ?>
                    <th><?php echo htmlspecialchars($base); ?></th>
                    <th><?php echo htmlspecialchars($base . ' (Log)'); ?></th>
                <?php endforeach; ?>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($data as $date => $row): ?>
                <?php
                    $dayOfWeek = date("l", strtotime($date)); 
                    $today = new DateTime('today');
                    $fileDate = new DateTime($date);
                    // Difference in whole days
                    $diffDays = (int)$today->diff($fileDate)->days;
                    if ($diffDays === 0 && $today == $fileDate) {
                        $daysAgo = "Today";
                    } elseif ($diffDays === 1 && $today > $fileDate) {
                        $daysAgo = "Yesterday";
                    } else {
                        $daysAgo = $diffDays . " days ago";
                    }
                ?>
                <tr>
                    <td><?php echo htmlspecialchars($dayOfWeek . ", " . $date); ?></td>
                    <td><?php echo htmlspecialchars($daysAgo); ?></td>
                    <?php foreach ($baseNames as $base): ?>
                        <?php if (isset($row[$base])): ?>
                            <td>
                                <a href="<?php echo urlencode($row[$base]['filename']); ?>" download>
                                    Download
                                </a>
                            </td>
                            <?php $logRel = logPathForBase($base, $folderNameLower); ?>
                            <td>
                                <?php if ($logRel && file_exists($logRel)): ?>
                                    <a href="<?php echo htmlspecialchars($logRel); ?>" target="_blank" rel="noopener">Log</a>
                                <?php else: ?>
                                    &nbsp;
                                <?php endif; ?>
                            </td>
                        <?php else: ?>
                            <td class="missing">&nbsp;</td>
                            <td class="missing">&nbsp;</td>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<script>
// Simple table sort
document.querySelectorAll("#reportTable th").forEach((th, idx) => {
    // Skip sorting for "Days Ago" column at index 1
    if (idx === 1) return;

    th.style.cursor = "pointer";
    th.addEventListener("click", () => {
        const table = th.closest("table");
        const rows = Array.from(table.querySelector("tbody").querySelectorAll("tr"));
        const asc = !th.classList.contains("sort-asc");

        // Clear sort classes on all headers
        table.querySelectorAll("th").forEach(th2 => th2.classList.remove("sort-asc", "sort-desc"));
        th.classList.add(asc ? "sort-asc" : "sort-desc");

        rows.sort((r1, r2) => {
            let t1 = r1.children[idx].textContent.trim();
            let t2 = r2.children[idx].textContent.trim();

            // Special case: Date column (index 0) sort by true Date value
            if (idx === 0) {
                t1 = new Date(t1.split(", ")[1]);
                t2 = new Date(t2.split(", ")[1]);
                return asc ? t1 - t2 : t2 - t1;
            }

            // Sort textual values for other columns
            return asc ? t1.localeCompare(t2) : t2.localeCompare(t1);
        });

        rows.forEach(r => table.querySelector("tbody").appendChild(r));
    });
});
</script>
</body>
</html>
$path = 'src\tcp_farm.cpp'
$raw = [IO.File]::ReadAllText($path)
# Repair: restore '    // Si el refresh corre' prefix and remove the stray blank line.
$pattern = "(    if \(m_stop\) \{ emit finishedOk\(false, `"stopped`"\); return; \})(\r?\n)(\r?\n)( en paralelo \(thread separado\), el farm espera a que)"
$repl = '$1$2    // Si el refresh corre$4'
$rx = [regex]$pattern
$new = $rx.Replace($raw, $repl, 1)
if ($new -eq $raw) { Write-Output 'NO MATCH' } else { [IO.File]::WriteAllText($path, $new); Write-Output 'FIXED' }

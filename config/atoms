# ATOM-LOCK-GUARD

## Règle
Suppression de `.git/index.lock` avant tout retry de commande Git.

## Mécanisme
- Détecter la présence de `.git/index.lock` avant toute opération Git
- Si présent : supprimer le fichier, tracer l'action dans le WAL avec horodatage
- Log : `[LOCK_GUARD] lock_found=true action=removed wal_entry=<id>`

## Application
```powershell
# Vérification et nettoyage atomique
$lockPath = Join-Path $repoPath ".git\index.lock"
if (Test-Path $lockPath) {
    Remove-Item $lockPath -Force
    Write-WAL "LOCK_GUARD: removed index.lock at $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')"
}
```
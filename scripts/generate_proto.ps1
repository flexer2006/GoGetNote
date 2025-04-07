$PROTO_DIR = "api"
$GO_OUT_DIR = "pkg/api"
$MODULE_PATH = "gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote"

if (Test-Path -Path $GO_OUT_DIR) {
    Remove-Item -Recurse -Force -Path $GO_OUT_DIR
    Write-Host "Директория $GO_OUT_DIR очищена" -ForegroundColor Yellow
}

New-Item -ItemType Directory -Path $GO_OUT_DIR -Force | Out-Null
Write-Host "Создана директория $GO_OUT_DIR" -ForegroundColor Green

$protoFiles = Get-ChildItem -Path $PROTO_DIR -Filter "*.proto" -Recurse | 
    Where-Object { $_.FullName -notlike "*api/google/*" }

Write-Host "Найдено $($protoFiles.Count) proto файлов для обработки" -ForegroundColor Cyan
$processedCount = 0

foreach ($protoFile in $protoFiles) {
    $relativePath = $protoFile.FullName.Replace((Get-Location).Path + '\', '').Replace('\', '/')
    Write-Host "Обработка файла: $relativePath" -ForegroundColor White

    $cmd = "protoc " +
           "--go_out=$GO_OUT_DIR " +
           "--go_opt=module=$MODULE_PATH/$GO_OUT_DIR " +
           "--go-grpc_out=$GO_OUT_DIR " +
           "--go-grpc_opt=module=$MODULE_PATH/$GO_OUT_DIR " +
           "-I. " +
           "$relativePath"
    
    $output = Invoke-Expression $cmd 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ОШИБКА при генерации кода для $relativePath" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
    } else {
        $processedCount++
        Write-Host "  ✓ Успешно обработан файл: $relativePath" -ForegroundColor Green
    }
}

# Вывод результатов
$generatedFileCount = (Get-ChildItem -Path $GO_OUT_DIR -Recurse -File).Count
Write-Host "`nРезультаты генерации:" -ForegroundColor White
Write-Host "  Успешно обработано файлов: $processedCount из $($protoFiles.Count)" -ForegroundColor Green
Write-Host "  Сгенерировано .go файлов: $generatedFileCount" -ForegroundColor Green

Write-Host "`nГенерация Go кода из proto файлов успешно завершена!" -ForegroundColor Green
Write-Host "Запускаю go mod tidy для обновления зависимостей..." -ForegroundColor Cyan
Invoke-Expression "go mod tidy"
#!/bin/bash

# Important constants
PROTO_DIR="api"
GO_OUT_DIR="pkg/api"
MODULE_PATH="gogetnote"

# Очистка и создание директории
if [ -d "$GO_OUT_DIR" ]; then
  rm -rf "$GO_OUT_DIR"
  echo -e "\e[33mДиректория $GO_OUT_DIR очищена\e[0m"
fi

mkdir -p "$GO_OUT_DIR"
echo -e "\e[32mСоздана директория $GO_OUT_DIR\e[0m"

# Create temp directory
TEMP_DIR=$(mktemp -d)
echo -e "\e[36mСоздана временная директория: $TEMP_DIR\e[0m"

# Create import mappings directory for standard protobuf files
IMPORT_MAPPINGS_DIR="$TEMP_DIR/include"
mkdir -p "$IMPORT_MAPPINGS_DIR"
echo -e "\e[36mСоздана директория для маппингов импорта: $IMPORT_MAPPINGS_DIR\e[0m"

# Create directories for well-known types
mkdir -p "$IMPORT_MAPPINGS_DIR/google/protobuf"
mkdir -p "$IMPORT_MAPPINGS_DIR/google/api"
mkdir -p "$IMPORT_MAPPINGS_DIR/api/google/protobuf"
mkdir -p "$IMPORT_MAPPINGS_DIR/api/google/api"

# Copy protobuf files to standard locations
echo -e "\e[36mКопирование стандартных protobuf файлов в каталог импортов...\e[0m"
cp -f "$PROTO_DIR/google/protobuf/timestamp.proto" "$IMPORT_MAPPINGS_DIR/google/protobuf/"
cp -f "$PROTO_DIR/google/protobuf/empty.proto" "$IMPORT_MAPPINGS_DIR/google/protobuf/"
cp -f "$PROTO_DIR/google/protobuf/descriptor.proto" "$IMPORT_MAPPINGS_DIR/google/protobuf/"
cp -f "$PROTO_DIR/google/api/http.proto" "$IMPORT_MAPPINGS_DIR/google/api/"
cp -f "$PROTO_DIR/google/api/annotations.proto" "$IMPORT_MAPPINGS_DIR/google/api/"

# Create symlinks for the custom import paths
ln -sf "$IMPORT_MAPPINGS_DIR/google/protobuf/timestamp.proto" "$IMPORT_MAPPINGS_DIR/api/google/protobuf/"
ln -sf "$IMPORT_MAPPINGS_DIR/google/protobuf/empty.proto" "$IMPORT_MAPPINGS_DIR/api/google/protobuf/"
ln -sf "$IMPORT_MAPPINGS_DIR/google/protobuf/descriptor.proto" "$IMPORT_MAPPINGS_DIR/api/google/protobuf/"
ln -sf "$IMPORT_MAPPINGS_DIR/google/api/http.proto" "$IMPORT_MAPPINGS_DIR/api/google/api/"
ln -sf "$IMPORT_MAPPINGS_DIR/google/api/annotations.proto" "$IMPORT_MAPPINGS_DIR/api/google/api/"

# Отладочная информация
echo -e "\e[36mТекущая директория: $(pwd)\e[0m"
echo -e "\e[36mИщем в директории: $PROTO_DIR\e[0m"
ALL_FILES=$(find "$PROTO_DIR" -type f | wc -l)
echo -e "\e[36mВсего файлов в директории: $ALL_FILES\e[0m"

# Поиск proto-файлов для обработки
PROTO_FILES=$(find "$PROTO_DIR" -name "*.proto" | grep -E 'api/auth|api/notes|api/common')
FILE_COUNT=$(echo "$PROTO_FILES" | wc -l)
echo -e "\e[36mНайдено $FILE_COUNT proto файлов для обработки\e[0m"

echo "$PROTO_FILES" | while read -r file; do
  echo -e "\e[37m  - $file\e[0m"
done

# Verify go_package options in proto files
echo -e "\e[36mПроверка опций go_package в proto файлах...\e[0m"
for proto_file in $PROTO_FILES; do
  go_package=$(grep -o 'go_package.*=.*' "$proto_file" | sed 's/.*= *"\(.*\)".*/\1/')
  echo -e "\e[37m  - $proto_file: go_package = $go_package\e[0m"
done

PROCESSED_COUNT=0

# Process each proto file
echo "$PROTO_FILES" | while read -r proto_file; do
  echo -e "\e[37mОбработка файла: $proto_file\e[0m"
  
  # Get directory components for output path mapping
  rel_path=${proto_file#$PROTO_DIR/}
  target_dir=$(dirname "$rel_path")
  
  # Create output directory
  mkdir -p "$GO_OUT_DIR/$target_dir"
  
# Обновите команду protoc, добавив путь для импорта из корня проекта:

CMD="protoc \
  --go_out=$GO_OUT_DIR \
  --go_opt=module=$MODULE_PATH/$GO_OUT_DIR \
  --go-grpc_out=$GO_OUT_DIR \
  --go-grpc_opt=module=$MODULE_PATH/$GO_OUT_DIR \
  --grpc-gateway_out=$GO_OUT_DIR \
  --grpc-gateway_opt=module=$MODULE_PATH/$GO_OUT_DIR \
  --grpc-gateway_opt=logtostderr=true \
  -I. \
  -I$PROTO_DIR/.. \
  -I$IMPORT_MAPPINGS_DIR \
  $proto_file"
  
  echo -e "\e[37mВыполняем: $CMD\e[0m"
  
  OUTPUT=$(eval "$CMD" 2>&1)
  
  if [ $? -ne 0 ]; then
    echo -e "\e[31mОШИБКА при генерации кода для $proto_file\e[0m"
    echo -e "\e[31m$OUTPUT\e[0m"
  else
    PROCESSED_COUNT=$((PROCESSED_COUNT + 1))
    echo -e "\e[32m  ✓ Успешно обработан файл: $proto_file\e[0m"
  fi
done

# Удаление временной директории
rm -rf "$TEMP_DIR"
echo -e "\e[36mВременная директория удалена\e[0m"

# Считаем сгенерированные файлы
GENERATED_FILES=$(find "$GO_OUT_DIR" -type f 2>/dev/null | wc -l)

echo -e "\n\e[37mРезультаты генерации:\e[0m"
echo -e "\e[32m  Успешно обработано файлов: $PROCESSED_COUNT из $FILE_COUNT\e[0m"
echo -e "\e[32m  Сгенерировано .go файлов: $GENERATED_FILES\e[0m"

# Fix imports in generated files if needed
echo -e "\e[36mПроверка сгенерированных файлов...\e[0m"
find "$GO_OUT_DIR" -name "*.go" -type f | while read -r file; do
  if grep -q "gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote" "$file"; then
    echo -e "\e[33mИсправление импортов в файле: $file\e[0m"
    sed -i 's|gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote|gogetnote|g' "$file"
  fi
  # Check if we need to move any files from incorrect locations
  if [[ "$file" != *"$GO_OUT_DIR"* ]]; then
    echo -e "\e[33mПеремещаем файл из неправильного расположения: $file\e[0m"
    target_dir="$GO_OUT_DIR/$(dirname "${file#./}")"
    mkdir -p "$target_dir"
    mv "$file" "$target_dir/"
  fi
done

echo -e "\n\e[32mГенерация Go кода из proto файлов успешно завершена!\e[0m"
echo -e "\e[36mЗапускаю go mod tidy для обновления зависимостей...\e[0m"
go mod tidy
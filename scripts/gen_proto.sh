#!/bin/bash
# filepath: scripts/gen_proto.sh

PROTO_DIR="api"
GO_OUT_DIR="pkg/api"
MODULE_PATH="gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote"

# Очистка и создание директории
if [ -d "$GO_OUT_DIR" ]; then
  rm -rf "$GO_OUT_DIR"
  echo -e "\e[33mДиректория $GO_OUT_DIR очищена\e[0m"
fi

mkdir -p "$GO_OUT_DIR"
echo -e "\e[32mСоздана директория $GO_OUT_DIR\e[0m"

# Отладочная информация
echo -e "\e[36mТекущая директория: $(pwd)\e[0m"
echo -e "\e[36mИщем в директории: $PROTO_DIR\e[0m"
ALL_FILES=$(find "$PROTO_DIR" -type f | wc -l)
echo -e "\e[36mВсего файлов в директории: $ALL_FILES\e[0m"

# Поиск proto-файлов
PROTO_FILES=$(find "$PROTO_DIR" -name "*.proto" | grep -E 'api/auth|api/notes|api/common')
FILE_COUNT=$(echo "$PROTO_FILES" | wc -l)
echo -e "\e[36mНайдено $FILE_COUNT proto файлов для обработки\e[0m"

echo "$PROTO_FILES" | while read -r file; do
  echo -e "\e[37m  - $file\e[0m"
done

PROCESSED_COUNT=0

# Обработка каждого файла
echo "$PROTO_FILES" | while read -r proto_file; do
  echo -e "\e[37mОбработка файла: $proto_file\e[0m"

  CMD="protoc \
    --go_out=$GO_OUT_DIR \
    --go_opt=module=$MODULE_PATH/$GO_OUT_DIR \
    --go-grpc_out=$GO_OUT_DIR \
    --go-grpc_opt=module=$MODULE_PATH/$GO_OUT_DIR \
    --grpc-gateway_out=$GO_OUT_DIR \
    --grpc-gateway_opt=module=$MODULE_PATH/$GO_OUT_DIR \
    --grpc-gateway_opt=logtostderr=true \
    -I. \
    -I$GOPATH/pkg/mod/github.com/googleapis/googleapis \
    -I$GOPATH/pkg/mod \
    -I$GOPATH/src \
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

# Считаем сгенерированные файлы
GENERATED_FILES=$(find "$GO_OUT_DIR" -type f | wc -l)

echo -e "\n\e[37mРезультаты генерации:\e[0m"
echo -e "\e[32m  Успешно обработано файлов: $PROCESSED_COUNT из $FILE_COUNT\e[0m"
echo -e "\e[32m  Сгенерировано .go файлов: $GENERATED_FILES\e[0m"

echo -e "\n\e[32mГенерация Go кода из proto файлов успешно завершена!\e[0m"
echo -e "\e[36mЗапускаю go mod tidy для обновления зависимостей...\e[0m"
go mod tidy